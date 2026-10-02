/** Monitoring: DNS record drift, reporter silence, stalled ingestion, auto-resolution. */
const { createChecker } = require("./helpers/assert");
const { openDatabase } = require("../db");
const { parseAggregateReport } = require("../dmarc-parser");
const { createDnsRecords } = require("../dns-records");
const { createMonitor, dmarcChangeSummary, REPORTER_SILENT_DAYS, INGEST_STALL_HOURS } = require("../monitor");
const { describeAlert } = require("../alerts");

const { check, report } = createChecker("Monitor: DNS drift, reporter silence, stalled ingestion");

const DAY = 86400;
const HOUR = 3600;
// Reports are stamped with the real clock when stored, so the checks run relative to it.
const NOW = Math.floor(Date.now() / 1000);
const db = openDatabase({ file: ":memory:" });
let seq = 0;

function reportXml({ org, domain = "example.com", begin, count = 10, selector = "s1" }) {
  seq += 1;
  return `<feedback><report_metadata><org_name>${org}</org_name><report_id>${org}-${seq}</report_id>
<date_range><begin>${begin}</begin><end>${begin + DAY - 1}</end></date_range></report_metadata>
<policy_published><domain>${domain}</domain><p>reject</p></policy_published>
<record><row><source_ip>203.0.113.10</source_ip><count>${count}</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
<identifiers><header_from>${domain}</header_from></identifiers>
<auth_results><dkim><domain>${domain}</domain><selector>${selector}</selector><result>pass</result></dkim><spf><domain>${domain}</domain><result>pass</result></spf></auth_results></record>
</feedback>`;
}

function ingest(spec) {
  const xml = reportXml(spec);
  return db.insertReport({ messageId: `m${seq + 1}`, parsed: parseAggregateReport(xml), xml }).reportId;
}

// Thirty days of daily reports from google.com, a one-off from a small reporter.
for (let d = 35; d >= 5; d -= 1) ingest({ org: "google.com", begin: NOW - d * DAY });
ingest({ org: "Tiny Mail Co", begin: NOW - 20 * DAY });
ingest({ org: "Tiny Mail Co", begin: NOW - 12 * DAY });

// --- a mutable zone behind the real dns-records module ---------------------------------------
const zone = {
  "_dmarc.example.com": [["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]],
  "example.com": [["v=spf1 ip4:203.0.113.0/24 -all"]],
  "s1._domainkey.example.com": [["v=DKIM1; k=rsa; p=MIIBIjANBgkq"]],
  "_mta-sts.example.com": [["v=STSv1; id=20260901"]],
  "_smtp._tls.example.com": [["v=TLSRPTv1; rua=mailto:tls@example.com"]]
};
let stsPolicy = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmax_age: 604800\n";
const fetchImpl = async () => ({ ok: true, status: 200, headers: { get: () => "text/plain" }, text: async () => stsPolicy });
const failing = new Set();
const notFound = () => { const e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e; };
const servfail = () => { const e = new Error("ESERVFAIL"); e.code = "ESERVFAIL"; throw e; };
const resolvers = {
  resolveTxt: async (name) => (failing.has(name) ? servfail() : zone[name] || notFound()),
  resolve4: async () => notFound(),
  resolve6: async () => notFound(),
  resolveMx: async () => notFound(),
  reverse: async () => notFound()
};
const dnsRecords = createDnsRecords({ resolvers, cacheTtlMs: 0, fetchImpl });
let enabledBoxes = [{ id: "env", name: "DMARC inbox", mailbox: "dmarc@example.com", enabled: true }];
const mailboxes = { list: () => enabledBoxes };
const monitor = createMonitor({ db, dnsRecords, mailboxes, logger: { warn() {} } });

(async () => {
  // --- DNS: baseline, then drift -----------------------------------------------------------
  let t = NOW;
  const first = await monitor.snapshotDns({ at: t });
  check("first snapshot is the baseline: nothing alerts", first.created.length === 0 && first.errors.length === 0 && first.domains === 1, JSON.stringify(first));
  const hist = db.dnsHistory("example.com");
  check("baseline stored one row per record, MTA-STS policy and TLS-RPT included", hist.length === 6 && hist.map((h) => h.kind).sort().join() === "dkim,dmarc,mta_sts,mta_sts_policy,spf,tlsrpt" && hist.every((h) => h.found === 1 && h.first_seen === t), JSON.stringify(hist));
  check("policy file text is what is tracked", db.dnsLatest("example.com", "mta_sts_policy").value === stsPolicy.trim());
  check("snapshot time remembered and not due again", monitor.lastSnapshotAt() === t && monitor.snapshotDue(t + HOUR) === false && monitor.snapshotDue(t + 25 * HOUR) === true);

  t += DAY;
  const same = await monitor.snapshotDns({ at: t });
  check("unchanged records: no alert, windows extended, no new rows", same.created.length === 0 && db.dnsHistory("example.com").length === 6 && db.dnsLatest("example.com", "dmarc").last_seen === t);

  zone["_dmarc.example.com"] = [["v=DMARC1; p=none; pct=50; rua=mailto:dmarc@example.com"]];
  zone["example.com"] = [["v=spf1 ip4:203.0.113.0/24 include:spf.protection.outlook.com -all"], ["other txt"]];
  zone["spf.protection.outlook.com"] = [["v=spf1 ip4:40.92.0.0/15 -all"]];
  delete zone["s1._domainkey.example.com"];
  stsPolicy = "version: STSv1\nmode: testing\nmx: mx1.example.com\nmax_age: 604800\n";
  delete zone["_smtp._tls.example.com"];
  t += DAY;
  const drift = await monitor.snapshotDns({ at: t });
  const byKey = Object.fromEntries(drift.created.map((a) => [a.key, a]));
  check("five changes, five alerts", drift.created.length === 5, JSON.stringify(drift.created.map((a) => a.key)));
  check("MTA-STS policy going from enforce to testing is high with the mode change", byKey["mta_sts_policy:example.com"] && byKey["mta_sts_policy:example.com"].severity === "high" && byKey["mta_sts_policy:example.com"].detail.summary === "mode enforce → testing" && byKey["mta_sts_policy:example.com"].title.includes("MTA-STS policy"), JSON.stringify(byKey["mta_sts_policy:example.com"]));
  check("vanished TLS-RPT record is high", byKey["tlsrpt:example.com"] && byKey["tlsrpt:example.com"].severity === "high" && byKey["tlsrpt:example.com"].title === "TLS-RPT record for example.com is gone");
  check("unchanged MTA-STS record itself did not alert", !byKey["mta_sts:example.com"]);
  check("weakened DMARC policy is high severity with a tag summary", byKey["dmarc:example.com"] && byKey["dmarc:example.com"].severity === "high" && byKey["dmarc:example.com"].detail.summary.includes("p=reject → none") && byKey["dmarc:example.com"].detail.summary.includes("pct=(unset) → 50"), JSON.stringify(byKey["dmarc:example.com"]));
  check("SPF change is medium and carries both values", byKey["spf:example.com"] && byKey["spf:example.com"].severity === "medium" && byKey["spf:example.com"].detail.previous.includes("-all") && byKey["spf:example.com"].detail.current.includes("outlook"));
  check("vanished DKIM key is high and says since when it stood", byKey["dkim:s1:example.com"] && byKey["dkim:s1:example.com"].severity === "high" && byKey["dkim:s1:example.com"].title.includes("is gone") && byKey["dkim:s1:example.com"].detail.previousSince === NOW);
  check("history grew by one row per change, newest first", db.dnsHistory("example.com").length === 11 && db.dnsHistory("example.com")[0].first_seen === t);
  for (const a of drift.created) {
    check(`webhook text for ${a.key} is readable`, !describeAlert(a).includes("[object") && describeAlert(a).length > 10, describeAlert(a));
  }

  // A resolver failure is not a vanished record.
  failing.add("example.com");
  t += DAY;
  const flaky = await monitor.snapshotDns({ at: t });
  check("SERVFAIL on SPF: no alert, error reported, history untouched", flaky.created.length === 0 && flaky.errors.length === 1 && flaky.errors[0].includes("SPF") && db.dnsHistory("example.com").length === 11, JSON.stringify(flaky));
  failing.clear();

  zone["_dmarc.example.com"] = [["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]];
  t += DAY;
  const back = await monitor.snapshotDns({ at: t });
  check("tightening the policy back is a medium change, not high", back.created.length === 1 && back.created[0].severity === "medium" && back.created[0].detail.summary.includes("p=none → reject"), JSON.stringify(back.created));

  const summary = dmarcChangeSummary("v=DMARC1; p=quarantine; pct=100; rua=mailto:a@x.test", "v=DMARC1; p=quarantine; pct=20; rua=mailto:b@x.test", dnsRecords.parseDmarcTags);
  check("change summary: lower pct weakens, rua change is listed", summary.weakened && summary.text.includes("pct=100 → 20") && summary.text.includes("rua a@x.test → b@x.test"), summary.text);

  // --- reporter silence --------------------------------------------------------------------
  const cadence = db.reporterCadence({ now: NOW });
  const g = cadence.find((c) => c.orgName === "google.com");
  check("cadence: daily reporter has a median gap of one day", g && g.medianGapDays === 1 && g.reportsBeforeLast >= 25 && g.lastSeen === NOW - 5 * DAY + DAY - 1, JSON.stringify(g));
  const quiet1 = monitor.checkReporters({ at: NOW });
  check("silent for 4 days: the regular reporter alerts, the occasional one does not", quiet1.created.length === 1 && quiet1.created[0].type === "reporter_silent" && quiet1.created[0].key === "google.com" && quiet1.created[0].detail.days === REPORTER_SILENT_DAYS, JSON.stringify(quiet1.created));
  check("not repeated on the next check", monitor.checkReporters({ at: NOW + HOUR }).created.length === 0);
  check("silence text is readable", describeAlert(quiet1.created[0]).includes("reports in the 30 days"), describeAlert(quiet1.created[0]));

  ingest({ org: "google.com", begin: NOW - DAY });
  const resumed = monitor.checkReporters({ at: NOW });
  check("a new report resolves the silence alert automatically", resumed.created.length === 0 && resumed.resolved.includes("google.com") && db.openAlerts().every((a) => a.type !== "reporter_silent") && db.recentAlerts().find((a) => a.type === "reporter_silent").acknowledged_by === "auto: reports resumed");

  // --- stalled ingestion -------------------------------------------------------------------
  check("ingestion fresh: nothing", monitor.checkIngest({ at: NOW }).created.length === 0);
  const stalled = monitor.checkIngest({ at: NOW + (INGEST_STALL_HOURS + 1) * HOUR });
  check("nothing stored for 49 hours with a mailbox enabled: high alert with mailbox detail", stalled.created.length === 1 && stalled.created[0].severity === "high" && stalled.created[0].detail.mailboxes[0].name === "DMARC inbox" && stalled.created[0].detail.hours >= INGEST_STALL_HOURS, JSON.stringify(stalled.created));
  check("not repeated while open", monitor.checkIngest({ at: NOW + 60 * HOUR }).created.length === 0);
  check("stall text is readable", describeAlert(stalled.created[0]).includes("never synced"), describeAlert(stalled.created[0]));
  ingest({ org: "google.com", begin: NOW - HOUR });
  const flowing = monitor.checkIngest({ at: NOW + HOUR });
  check("a stored report resolves the stall", flowing.resolved.length === 1 && db.openAlerts().every((a) => a.type !== "ingest_stalled"));
  enabledBoxes = [];
  check("no enabled mailbox: never a stall alert", monitor.checkIngest({ at: NOW + 400 * HOUR }).created.length === 0);
  enabledBoxes = [{ id: "env", name: "DMARC inbox", mailbox: "dmarc@example.com", enabled: true }];

  // --- everything at once ------------------------------------------------------------------
  const all = await monitor.runAll({ at: t + HOUR, force: true });
  check("runAll: snapshot ran (forced) and health checks ran", all.dnsSnapshot === true && all.domains === 1 && Array.isArray(all.created) && Array.isArray(all.resolved));
  const skip = await monitor.runAll({ at: t + 2 * HOUR });
  check("runAll: snapshot skipped when not due", skip.dnsSnapshot === false);
  const desc = monitor.describe();
  check("describe: last snapshot, tracked domains and thresholds", desc.lastDnsSnapshotAt === t + HOUR && desc.trackedDomains.includes("example.com") && desc.thresholds.reporterSilentDays === REPORTER_SILENT_DAYS && desc.running === false, JSON.stringify({ desc, expected: t + HOUR }));

  db.close();
  process.exit(report() ? 0 : 1);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
