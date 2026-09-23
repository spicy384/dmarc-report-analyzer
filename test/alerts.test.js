/** Alert evaluation after a sync: new sources, spikes, new reporters, acknowledgement. */
const { createChecker } = require("./helpers/assert");
const { openDatabase } = require("../db");
const { parseAggregateReport } = require("../dmarc-parser");
const { evaluateAfterSync } = require("../alerts");

const { check, report } = createChecker("Alerts: new sources, spikes, reporters");
const db = openDatabase({ file: ":memory:" });

const DAY = 86400;
const NOW = 1790000000; // 2026-09-21T14:13:20Z
let seq = 0;

function reportXml({ org, domain = "example.com", begin, records }) {
  seq += 1;
  return `<feedback><report_metadata><org_name>${org}</org_name><report_id>${org}-${seq}</report_id>
<date_range><begin>${begin}</begin><end>${begin + DAY - 1}</end></date_range></report_metadata>
<policy_published><domain>${domain}</domain><p>quarantine</p></policy_published>
${records.map((r) => `<record><row><source_ip>${r.ip}</source_ip><count>${r.count}</count><policy_evaluated><disposition>${r.pass ? "none" : "quarantine"}</disposition><dkim>${r.pass ? "pass" : "fail"}</dkim><spf>${r.pass ? "pass" : "fail"}</spf>${r.forwarded ? "<reason><type>forwarded</type></reason>" : ""}</policy_evaluated></row><identifiers><header_from>${domain}</header_from></identifiers><auth_results><spf><domain>${r.pass ? domain : "x.test"}</domain><result>${r.pass ? "pass" : "softfail"}</result></spf></auth_results></record>`).join("")}
</feedback>`;
}

function ingest(spec) {
  const xml = reportXml(spec);
  const res = db.insertReport({ messageId: `m${seq}`, parsed: parseAggregateReport(xml), xml });
  return res.reportId;
}

// --- baseline: two weeks of history, nothing alerts on the first evaluation of old data ------
const oldIds = [];
for (let d = 14; d >= 8; d -= 1) {
  oldIds.push(ingest({ org: "google.com", begin: NOW - d * DAY, records: [{ ip: "203.0.113.10", count: 50, pass: true }, { ip: "198.51.100.7", count: 3 }] }));
}
db.setPtr("198.51.100.7", "old-spammer.test");
// Evaluated a week ago, as it would have been in real life.
const first = evaluateAfterSync({ db, addedReportIds: oldIds, now: NOW - 8 * DAY });
check("first evaluation: everything is new, so one new_source and one new_reporter", first.created.length === 2
  && first.created.some((a) => a.type === "new_source" && a.key === "198.51.100.7")
  && first.created.some((a) => a.type === "new_reporter" && a.key === "google.com"), JSON.stringify(first.created.map((a) => a.type + ":" + a.key)));
check("passing source is not an alert", !first.created.some((a) => a.key === "203.0.113.10"));
check("alert detail carries context", first.created[0].detail.ptr === "old-spammer.test" && first.created[0].detail.failed === 21 && first.created[0].severity === "high");
check("open alerts listed newest first", db.openAlerts().length === 2 && db.openAlertCount() === 2);

// --- second sync: a known sender, a brand-new spoofer, and a spike -------------------------
db.addKnownSender({ pattern: "40.107.0.0/16", kind: "ours", label: "Microsoft 365" });
const newIds = [];
for (let d = 7; d >= 1; d -= 1) {
  newIds.push(ingest({ org: "google.com", begin: NOW - d * DAY, records: [
    { ip: "203.0.113.10", count: 50, pass: true },
    { ip: "198.51.100.7", count: 5 },                 // 35 recent vs 21 previous: no spike (< 3x)
    { ip: "185.220.101.7", count: 8 },                // brand new spoofer: new_source
    { ip: "40.107.22.51", count: 4 },                 // ours, failing: known sender, no new_source
    { ip: "2001:db8::25", count: 6, forwarded: true } // forwarded fails never count for spikes
  ] }));
}
newIds.push(ingest({ org: "Enterprise Outlook", begin: NOW - DAY, records: [{ ip: "45.83.64.12", count: 2 }] }));
const second = evaluateAfterSync({ db, addedReportIds: newIds, now: NOW });
const types = second.created.map((a) => `${a.type}:${a.key}`).sort();
check("new spoofer alerts", types.includes("new_source:185.220.101.7"));
check("small new source is medium severity", second.created.find((a) => a.key === "185.220.101.7").severity === "high" && second.created.find((a) => a.key === "45.83.64.12").severity === "medium");
check("known sender does not alert as a new source", !types.includes("new_source:40.107.22.51"));
check("forwarded-only new source still alerts (it failed)", types.includes("new_source:2001:db8::25"));
check("new reporter alert", types.includes("new_reporter:Enterprise Outlook"));
check("no spike for a source that merely continued, nor for the brand-new one", !types.includes("spike:198.51.100.7") && !types.includes("spike:185.220.101.7"));
check("a known-ours sender that starts failing is a spike, with its label", types.includes("spike:40.107.22.51") && second.created.find((a) => a.key === "40.107.22.51").detail.sender.label === "Microsoft 365");
check("existing source is not new again", !types.includes("new_source:198.51.100.7"));

// --- third sync: a real spike from an old source ------------------------------------------
const spikeIds = [ingest({ org: "google.com", begin: NOW - DAY + 100, records: [{ ip: "198.51.100.7", count: 80 }] })];
const third = evaluateAfterSync({ db, addedReportIds: spikeIds, now: NOW });
check("spike detected (115 recent vs 21 previous)", third.created.length === 1 && third.created[0].type === "spike" && third.created[0].key === "198.51.100.7" && third.created[0].detail.recent === 115 && third.created[0].detail.previous === 21, JSON.stringify(third.created));
const again = evaluateAfterSync({ db, addedReportIds: [ingest({ org: "google.com", begin: NOW - DAY + 200, records: [{ ip: "198.51.100.7", count: 10 }] })], now: NOW });
check("spike not repeated within the window", again.created.length === 0);
check("no added reports means nothing to do", evaluateAfterSync({ db, addedReportIds: [], now: NOW }).created.length === 0);

// --- acknowledgement ------------------------------------------------------------------------
const open = db.openAlerts();
check("eight open alerts", open.length === 8, String(open.length));
check("ack one", db.ackAlert(open[0].id, "admin") === true && db.openAlertCount() === 7 && db.ackAlert(open[0].id, "admin") === false);
check("acked alert is no longer open but still recent", db.recentAlerts().some((a) => a.id === open[0].id && a.acknowledged_by === "admin"));
check("ack all", db.ackAllAlerts("admin") === 7 && db.openAlertCount() === 0);
check("new_source stays quiet for 90 days after acknowledging", (() => {
  const ids = [ingest({ org: "google.com", begin: NOW, records: [{ ip: "185.220.101.7", count: 9 }] })];
  return evaluateAfterSync({ db, addedReportIds: ids, now: NOW }).created.length === 0;
})());

db.close();
process.exit(report() ? 0 : 1);
