/** Retention: rolling old reports into daily totals and removing their records and XML. */
const { createChecker } = require("./helpers/assert");
const { openDatabase } = require("../db");
const { parseAggregateReport } = require("../dmarc-parser");
const { createRetention, cutoffFor } = require("../retention");

const { check, report } = createChecker("Retention: rollups, purge, summary continuity");
const db = openDatabase({ file: ":memory:" });
const DAY = 86400;
const NOW = Date.UTC(2026, 8, 23) ; // 2026-09-23 UTC, milliseconds
let seq = 0;

function ingest({ org = "google.com", domain = "example.com", mailboxId = "env", begin, records }) {
  seq += 1;
  const xml = `<feedback><report_metadata><org_name>${org}</org_name><report_id>r${seq}</report_id>
<date_range><begin>${begin}</begin><end>${begin + DAY - 1}</end></date_range></report_metadata>
<policy_published><domain>${domain}</domain><p>quarantine</p></policy_published>
${records.map((r) => `<record><row><source_ip>${r.ip}</source_ip><count>${r.count}</count><policy_evaluated><disposition>${r.disposition || (r.pass ? "none" : "quarantine")}</disposition><dkim>${r.pass ? "pass" : "fail"}</dkim><spf>${r.pass ? "pass" : "fail"}</spf>${r.forwarded ? "<reason><type>forwarded</type></reason>" : ""}</policy_evaluated></row><identifiers><header_from>${domain}</header_from></identifiers><auth_results><spf><domain>${domain}</domain><result>${r.pass ? "pass" : "fail"}</result></spf></auth_results></record>`).join("")}
</feedback>`;
  db.recordMessage({ graphId: `m${seq}`, mailboxId, receivedAt: begin + DAY, subject: "r", fromAddr: "x@y", status: "ingested" });
  return db.insertReport({ messageId: `m${seq}`, mailboxId, attachmentName: `r${seq}.xml`, parsed: parseAggregateReport(xml), xml }).reportId;
}

check("cutoffFor: calendar months at UTC midnight", cutoffFor(3, NOW) === Date.UTC(2026, 5, 23) / 1000 && cutoffFor(12, NOW) === Date.UTC(2025, 8, 23) / 1000);

// Old data: 200 days ago (two reports on the same day, two domains), 100 days ago; recent: 5 days ago.
const nowSec = NOW / 1000;
const oldDay = nowSec - 200 * DAY;
const oldA = ingest({ begin: oldDay, records: [{ ip: "203.0.113.10", count: 40, pass: true }, { ip: "198.51.100.7", count: 6 }, { ip: "192.0.2.5", count: 2, forwarded: true }] });
const oldB = ingest({ org: "Yahoo", begin: oldDay, records: [{ ip: "203.0.113.10", count: 10, pass: true }, { ip: "198.51.100.7", count: 4, disposition: "reject" }] });
const oldShop = ingest({ domain: "shop.example.com", mailboxId: "box2", begin: oldDay + 3600, records: [{ ip: "203.0.113.10", count: 5, pass: true }] });
const midId = ingest({ begin: nowSec - 100 * DAY, records: [{ ip: "203.0.113.10", count: 20, pass: true }, { ip: "185.220.101.7", count: 3 }] });
const recentId = ingest({ begin: nowSec - 5 * DAY, records: [{ ip: "203.0.113.10", count: 30, pass: true }, { ip: "185.220.101.7", count: 9 }] });

const before = db.summary();
check("before purge: everything comes from records", before.totals.messages === 129 && before.totals.failed === 24 && before.totals.likelyForwards === 2 && before.totals.rolledUpReports === 0);

// --- disabled retention does nothing ----------------------------------------
const off = createRetention({ db, months: 0, logger: { log() {}, error() {} } });
check("disabled: purge is a no-op", off.purge().skipped === true && off.describe().enabled === false && off.start() === false);

// --- 4 months: only the 200-day-old reports go ------------------------------
const four = createRetention({ db, months: 4, logger: { log() {}, error() {} } });
const r1 = four.purge({ now: NOW });
check("purge rolled up the three old reports", r1.reports === 3 && r1.records === 6 && r1.days === 2, JSON.stringify(r1));
check("records of purged reports are gone", db.reportById(oldA).records.length === 0 && db.reportById(recentId).records.length === 2);
check("xml of purged reports is gone, recent kept", db.reportXml(oldA) === null && db.reportXml(recentId) !== null);
check("report rows stay and are marked", db.reportById(oldA).purgedAt > 0 && db.reportById(oldA).messages === 48 && db.reports().total === 5);

const totals = db.dailyTotals();
check("daily totals per day/domain/mailbox", totals.length === 2 && totals.find((t) => t.domain === "example.com").reports === 2 && totals.find((t) => t.domain === "example.com").total === 62 && totals.find((t) => t.domain === "example.com").pass === 50 && totals.find((t) => t.domain === "example.com").fail_forward === 2 && totals.find((t) => t.domain === "example.com").fail_quarantine === 6 && totals.find((t) => t.domain === "example.com").fail_reject === 4);
check("shop domain rolled up under its mailbox", totals.find((t) => t.domain === "shop.example.com").mailbox_id === "box2" && totals.find((t) => t.domain === "shop.example.com").total === 5);

const after = db.summary();
check("summary totals unchanged by the purge", after.totals.messages === 129 && after.totals.failed === 24 && after.totals.likelyForwards === 2 && after.totals.quarantined === before.totals.quarantined && after.totals.quarantined === 20 && after.totals.rejected === before.totals.rejected && after.totals.rolledUpReports === 3, JSON.stringify(after.totals));
check("summary still counts every report and reporter", after.totals.reports === 5 && after.totals.reporters === 2);
check("day series includes the rolled-up day", after.days.length === 3 && after.days[0].day === new Date(oldDay * 1000).toISOString().slice(0, 10) && after.days[0].total === 67 && after.days[0].failForward === 2 && after.days[0].fail === 12);
check("sources only cover retained records", !db.ips().some((r) => r.ip === "198.51.100.7") && db.ips().find((r) => r.ip === "203.0.113.10").total === 50);
check("domain and mailbox filters apply to rollups", db.summary({ domain: "shop.example.com" }).totals.messages === 5 && db.summary({ mailbox: "box2" }).totals.messages === 5 && db.summary({ domain: "example.com" }).totals.messages === 124);
check("window filter applies to rollups", db.summary({ from: oldDay - DAY, to: oldDay + DAY }).totals.messages === 67 && db.summary({ from: nowSec - 150 * DAY }).totals.messages === 62);
check("excludeForwards drops rolled-up forwards", db.summary({ excludeForwards: true }).totals.messages === 127 && db.summary({ excludeForwards: true }).totals.likelyForwards === 0);
check("search ignores rollups (records only)", db.summary({ q: "203.0.113.10" }).totals.messages === 50);

const r2 = four.purge({ now: NOW });
check("second purge is a no-op", r2.reports === 0 && r2.records === 0);
const info = four.describe();
check("describe", info.enabled && info.months === 4 && info.purgedReports === 3 && info.rolledUpDays === 2 && info.rolledUpMessages === 67 && info.earliestRetained === nowSec - 100 * DAY && info.cutoff === cutoffFor(4, Date.now()));

// --- tighter retention later rolls the 100-day report into the same table -----
const two = createRetention({ db, months: 2, logger: { log() {}, error() {} } });
const r3 = two.purge({ now: NOW });
check("later, stricter purge takes the next report", r3.reports === 1 && db.summary().totals.messages === 129 && db.dailyTotals().length === 3);
check("scheduler starts when enabled", two.start() === true);
two.stop();

db.close();
process.exit(report() ? 0 : 1);
