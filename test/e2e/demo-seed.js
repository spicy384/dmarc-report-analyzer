/**
 * A demo dataset for screenshots: sixty days of aggregate reports for example.com
 * from three reporters, with the usual cast (the mail platform passing, a marketing
 * service half set up, a forwarder, and a spoofer that ramps up at the end), plus a
 * TLS report, a forensic report, labels, reverse DNS and geography. Everything is
 * synthetic: documentation domains and addresses only.
 */
const fs = require("fs");
const path = require("path");

const PROJECT = path.join(__dirname, "..", "..");
const { openDatabase } = require(path.join(PROJECT, "db"));
const { parseAggregateReport } = require(path.join(PROJECT, "dmarc-parser"));
const { createIngest } = require(path.join(PROJECT, "ingest"));
const { evaluateAfterSync } = require(path.join(PROJECT, "alerts"));

const DAY = 86400;

const SOURCES = [
  { ip: "40.107.22.51", ptr: "mail-bn8nam12on2051.outbound.protection.outlook.com", geo: ["US", "United States", "Boydton", 8075, "Microsoft Corporation"], base: 180, kind: "pass" },
  { ip: "40.107.93.74", ptr: "mail-dm6nam10on2074.outbound.protection.outlook.com", geo: ["US", "United States", "Des Moines", 8075, "Microsoft Corporation"], base: 95, kind: "pass" },
  { ip: "167.89.12.34", ptr: "o1.ptr1234.sendgrid.net", geo: ["US", "United States", "Denver", 11377, "SendGrid, Inc."], base: 60, kind: "dkim-only" },
  { ip: "198.2.134.10", ptr: "mail134-10.atl141.mcsv.net", geo: ["US", "United States", "Atlanta", 14782, "The Rocket Science Group, LLC"], base: 24, kind: "unaligned" },
  { ip: "209.85.220.41", ptr: "mail-sor-f41.google.com", geo: ["US", "United States", "Mountain View", 15169, "Google LLC"], base: 9, kind: "forward" },
  { ip: "185.220.101.7", ptr: null, geo: ["DE", "Germany", "Berlin", 205100, "F3 Netze e.V."], base: 0, kind: "spoof", ramp: true },
  { ip: "45.83.64.12", ptr: null, geo: ["NL", "Netherlands", "Amsterdam", 208843, "Alpha Strike Labs GmbH"], base: 3, kind: "spoof" }
];
const REPORTERS = [["google.com", "noreply-dmarc-support@google.com", 0.5], ["Enterprise Outlook", "dmarcreport@microsoft.com", 0.35], ["Yahoo", "dmarchelp@yahooinc.com", 0.15]];

function recordXml(source, count, domain) {
  const evaluated = { pass: ["none", "pass", "pass"], "dkim-only": ["none", "pass", "fail"], unaligned: ["quarantine", "fail", "fail"], forward: ["none", "fail", "fail"], spoof: ["quarantine", "fail", "fail"] }[source.kind];
  const reason = source.kind === "forward" ? "<reason><type>forwarded</type><comment>looks forwarded</comment></reason>" : "";
  const dkim = source.kind === "pass" ? `<dkim><domain>${domain}</domain><selector>selector1</selector><result>pass</result></dkim>`
    : source.kind === "dkim-only" ? `<dkim><domain>${domain}</domain><selector>s1</selector><result>pass</result></dkim>`
      : source.kind === "unaligned" ? "<dkim><domain>mcsv.net</domain><selector>k1</selector><result>pass</result></dkim>"
        : source.kind === "forward" ? `<dkim><domain>${domain}</domain><selector>selector1</selector><result>fail</result></dkim>` : "";
  const spfDomain = source.kind === "pass" ? domain : source.kind === "dkim-only" ? "em1234.sendgrid.net" : source.kind === "unaligned" ? "mail134-10.atl141.mcsv.net" : source.kind === "forward" ? "forwarder.example.org" : "mail.attacker.example.net";
  const spfResult = source.kind === "spoof" ? "fail" : "pass";
  return `<record><row><source_ip>${source.ip}</source_ip><count>${count}</count><policy_evaluated><disposition>${evaluated[0]}</disposition><dkim>${evaluated[1]}</dkim><spf>${evaluated[2]}</spf>${reason}</policy_evaluated></row>
<identifiers><header_from>${domain}</header_from></identifiers><auth_results>${dkim}<spf><domain>${spfDomain}</domain><result>${spfResult}</result></spf></auth_results></record>`;
}

function reportXml({ org, email, id, begin, domain, records }) {
  return `<?xml version="1.0"?><feedback><report_metadata><org_name>${org}</org_name><email>${email}</email><report_id>${id}</report_id>
<date_range><begin>${begin}</begin><end>${begin + DAY - 1}</end></date_range></report_metadata>
<policy_published><domain>${domain}</domain><adkim>r</adkim><aspf>r</aspf><p>quarantine</p><sp>quarantine</sp><pct>100</pct></policy_published>
${records.join("\n")}</feedback>`;
}

/** Fills `dataDir` with the demo data and returns how much was stored. */
function seedDemo(dataDir) {
  const db = openDatabase({ dataDir });
  const today = Math.floor(Date.now() / 1000 / DAY) * DAY;
  const lastIds = [];
  let n = 0;
  for (let d = 60; d >= 1; d -= 1) {
    const begin = today - d * DAY;
    const weekday = new Date(begin * 1000).getUTCDay();
    const quiet = weekday === 0 || weekday === 6 ? 0.35 : 1;
    for (const [org, email, share] of REPORTERS) {
      const records = [];
      for (const s of SOURCES) {
        // A little deterministic variety per day, and a spoofer that appears in the last week and grows.
        const wobble = 0.8 + ((d * 7 + s.ip.length * 3) % 9) / 20;
        let count = Math.round(s.base * share * quiet * wobble);
        if (s.ramp) count = d <= 6 ? Math.round((7 - d) * 14 * share) : 0;
        if (count > 0) records.push(recordXml(s, count, "example.com"));
      }
      if (!records.length) continue;
      n += 1;
      const xml = reportXml({ org, email, id: `demo-${org.replace(/\W+/g, "")}-${d}`, begin, domain: "example.com", records });
      db.recordMessage({ graphId: `demo-${n}`, receivedAt: begin + DAY + 3600, subject: `Report domain: example.com Submitter: ${org}`, fromAddr: email, status: "ingested" });
      const result = db.insertReport({ messageId: `demo-${n}`, attachmentName: `${org}!example.com!${begin}!${begin + DAY - 1}.xml`, parsed: parseAggregateReport(xml), xml });
      if (d <= 2) lastIds.push(result.reportId);
    }
  }
  for (const s of SOURCES) {
    if (s.ptr) db.setPtr(s.ip, s.ptr);
    db.setGeo(s.ip, { countryCode: s.geo[0], country: s.geo[1], city: s.geo[2], asn: s.geo[3], asOrg: s.geo[4], source: "file" });
  }
  db.addKnownSender({ pattern: "*.outbound.protection.outlook.com", kind: "ours", label: "Microsoft 365" });
  db.addKnownSender({ pattern: "*.sendgrid.net", kind: "vendor", label: "SendGrid (invoices)" });

  const ingest = createIngest({ db });
  const tls = fs.readFileSync(path.join(PROJECT, "examples", "tls-report.json"), "utf8");
  for (let d = 5; d >= 1; d -= 1) {
    const begin = new Date((today - d * DAY) * 1000).toISOString().slice(0, 10);
    const shifted = tls.replace(/2026-09-28/g, begin).replace("5065427c-23d3-47ca-b6e0-946ea0e8c4be", `demo-tls-${d}`)
      .replace('"total-failure-session-count": 303', `"total-failure-session-count": ${d === 3 ? 303 : 0}`)
      .replace(/"failure-details": \[[\s\S]*\]\s*\}\s*\]\s*\}\s*$/, d === 3 ? "$&" : '"failure-details": []\n    }\n  ]\n}\n');
    ingest.ingestBytes({ bytes: Buffer.from(shifted), name: `company-x!example.com!${d}.json`, messageId: `demo-tls-${d}`, mailboxId: "env" });
  }
  ingest.ingestEmail({ raw: fs.readFileSync(path.join(PROJECT, "examples", "forensic-report.eml")), name: "forensic.eml", messageId: "demo-forensic", mailboxId: "env" });

  const alerts = evaluateAfterSync({ db, addedReportIds: lastIds }).created.length;
  const stats = db.stats();
  db.close();
  return { reports: stats.reports.reports, messages: stats.reports.messages, alerts };
}

module.exports = { seedDemo };
