/** Storage and aggregation tests against an in-memory database. */
const fs = require("fs");
const path = require("path");

const { createChecker } = require("./helpers/assert");
const { openDatabase } = require("../db");
const { parseAggregateReport } = require("../dmarc-parser");

const { check, report } = createChecker("DB: ingest, dedupe, aggregation, filters");
const EX = path.join(__dirname, "..", "examples");
const googleXml = fs.readFileSync(path.join(EX, "google-aggregate.xml"), "utf8");
const microsoftXml = fs.readFileSync(path.join(EX, "microsoft-aggregate.xml"), "utf8");

const db = openDatabase({ file: ":memory:" });

// Google: 42 pass + 3 fail (quarantine) over 2 IPs, window begins 1758153600 (2025-09-18 UTC)
// Microsoft: 1 pass + 7 fail (reject) over 2 IPs, same window
db.recordMessage({ graphId: "m1", receivedAt: 1758300000, subject: "Report Domain: example.com", fromAddr: "noreply-dmarc-support@google.com", status: "ingested" });
db.recordMessage({ graphId: "m2", receivedAt: 1758310000, subject: "Report", fromAddr: "dmarcreport@microsoft.com", status: "ingested" });

const g = db.insertReport({ messageId: "m1", attachmentName: "google.zip", parsed: parseAggregateReport(googleXml), xml: googleXml });
check("google report inserted", g.duplicate === false && g.reportId > 0 && g.messages === 45 && g.passed === 42);

const m = db.insertReport({ messageId: "m2", attachmentName: "ms.xml.gz", parsed: parseAggregateReport(microsoftXml), xml: microsoftXml });
check("microsoft report inserted", m.duplicate === false && m.messages === 8 && m.passed === 1);

const dup = db.insertReport({ messageId: "m3", attachmentName: "google-again.zip", parsed: parseAggregateReport(googleXml), xml: googleXml });
check("same org+report_id+domain is ignored", dup.duplicate === true && dup.reportId === null);

check("message tracking", db.hasMessage("m1") && !db.hasMessage("nope"));
check("latest received", db.latestMessageReceivedAt() === 1758310000);

// --- summary ----------------------------------------------------------------

const s = db.summary();
check("summary messages", s.totals.messages === 53);
check("summary pass/fail", s.totals.passed === 43 && s.totals.failed === 10);
check("summary fail pct", s.totals.failPct === 18.9);
check("summary dispositions", s.totals.quarantined === 3 && s.totals.rejected === 7);
check("summary counts", s.totals.reports === 2 && s.totals.reporters === 2 && s.totals.sourceIps === 4 && s.totals.failingIps === 2);
check("summary day series", s.days.length === 1 && s.days[0].day === "2025-09-18" && s.days[0].pass === 43 && s.days[0].failQuarantine === 3 && s.days[0].failReject === 7);
check("summary top reporters", s.topReporters[0].orgName === "google.com" && s.topReporters[0].messages === 45);
check("summary top failing ips", s.topFailingIps.length === 2 && s.topFailingIps[0].ip === "192.0.2.99");

// --- ips --------------------------------------------------------------------

const all = db.ips();
check("ips: all four", all.length === 4);
const worst = all[0];
check("ips: sorted by failures", worst.ip === "192.0.2.99" && worst.failed === 7 && worst.rejected === 7);
check("ips: fail pct", worst.failPct === 100);
check("ips: domains seen", worst.spfDomains.includes("example.com") && worst.reporterNames.includes("Enterprise Outlook"));
const failing = db.ips({}, { failingOnly: true });
check("ips: failing only", failing.length === 2 && failing.every((r) => r.failed > 0));
const good = all.find((r) => r.ip === "203.0.113.10");
check("ips: passing sender", good.passed === 42 && good.failed === 0 && good.dkimPassed === 42);

db.setPtr("192.0.2.99", "mail.badhost.test");
db.setPtr("203.0.113.10", null);
check("ips missing ptr", db.ipsMissingPtr().length === 2);
const detail = db.ipDetail("192.0.2.99");
check("ip detail with ptr and records", detail.ptr === "mail.badhost.test" && detail.records.length === 1 && detail.records[0].reasons.length === 2);
check("ip detail unknown ip", db.ipDetail("10.9.9.9") === null);

// --- records / reports / reporters / domains --------------------------------

const failRecords = db.records({}, { result: "fail" });
check("records: fail filter", failRecords.total === 2 && failRecords.rows.every((r) => r.passed === false));
const byIp = db.records({}, { ip: "2001:db8::25" });
check("records: ip filter with joined report fields", byIp.total === 1 && byIp.rows[0].orgName === "Enterprise Outlook" && byIp.rows[0].dkimResults.length === 2);
const paged = db.records({}, { page: 2, pageSize: 3 });
check("records: paging", paged.total === 4 && paged.rows.length === 1 && paged.page === 2);

const reps = db.reports();
check("reports: list", reps.total === 2 && reps.rows[0].failed >= 0 && reps.rows.some((r) => r.receivedAt === 1758300000));
const byOrg = db.reports({}, { org: "google.com" });
check("reports: org filter", byOrg.total === 1 && byOrg.rows[0].attachmentName === "google.zip");
const one = db.reportById(g.reportId);
check("report by id with records", one && one.records.length === 2 && one.subject === "Report Domain: example.com");
check("report by id missing", db.reportById(9999) === null);
const xml = db.reportXml(g.reportId);
check("report xml round-trips", xml.fileName === "google.xml" && xml.xml === googleXml);

const reporters = db.reporters();
check("reporters", reporters.length === 2 && reporters[1].orgName === "Enterprise Outlook" && reporters[1].failPct === 87.5);
const domains = db.domains();
check("domains", domains.length === 1 && domains[0].domain === "example.com" && domains[0].messages === 53);

// --- filters ----------------------------------------------------------------

check("filter: explicit nulls mean unbounded", db.summary({ from: null, to: null, domain: null }).totals.messages === 53 && db.ips({ from: null, to: "" }).length === 4);
check("filter: window excludes everything", db.summary({ from: 1758240000 }).totals.messages === 0);
check("filter: window includes everything", db.summary({ from: 1758153600, to: 1758153601 }).totals.messages === 53);
check("filter: domain match is case-insensitive", db.summary({ domain: "EXAMPLE.COM" }).totals.messages === 53);
check("filter: other domain", db.summary({ domain: "other.test" }).totals.reports === 0);
check("filter: ips honour window", db.ips({ to: 1758153600 }).length === 0);

// --- likely forwards and search ---------------------------------------------

const forwardedXml = `<feedback><report_metadata><org_name>Yahoo</org_name><email>dmarchelp@yahooinc.com</email><report_id>y-1</report_id>
<date_range><begin>1758153600</begin><end>1758239999</end></date_range></report_metadata>
<policy_published><domain>example.com</domain><p>quarantine</p></policy_published>
<record><row><source_ip>10.10.10.10</source_ip><count>5</count><policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf>
<reason><type>forwarded</type></reason></policy_evaluated></row><identifiers><header_from>example.com</header_from><envelope_from>lists.forwarder.test</envelope_from></identifiers>
<auth_results><dkim><domain>example.com</domain><result>fail</result></dkim><spf><domain>lists.forwarder.test</domain><result>pass</result></spf></auth_results></record></feedback>`;
db.recordMessage({ graphId: "m4", receivedAt: 1758330000, subject: "yahoo", fromAddr: "dmarchelp@yahooinc.com", status: "ingested" });
const y = db.insertReport({ messageId: "m4", attachmentName: "yahoo.zip", parsed: parseAggregateReport(forwardedXml), xml: forwardedXml });
check("forwarded report inserted", y.duplicate === false && y.messages === 5 && y.passed === 0);

const withFwd = db.summary();
check("summary counts likely forwards", withFwd.totals.likelyForwards === 5 && withFwd.totals.failed === 15 && withFwd.totals.messages === 58);
const noFwd = db.summary({ excludeForwards: true });
check("excludeForwards drops them from totals and days", noFwd.totals.failed === 10 && noFwd.totals.messages === 53 && noFwd.days[0].fail === 10 && noFwd.days[0].failForward === 0);
check("day series splits forwards out of the disposition buckets", withFwd.days[0].failForward === 5 && withFwd.days[0].failQuarantine === 3 && withFwd.days[0].fail === 15);
check("excludeForwards keeps report counts", noFwd.totals.reports === 3);
const fwdIp = db.ips({}, { failingOnly: true }).find((r) => r.ip === "10.10.10.10");
check("ips carry likelyForwards", fwdIp && fwdIp.likelyForwards === 5 && fwdIp.failed === 5);
check("ips honour excludeForwards", db.ips({ excludeForwards: true }, { failingOnly: true }).length === 2);
check("records expose likelyForward", db.records({}, { ip: "10.10.10.10" }).rows[0].likelyForward === true && db.records({}, { ip: "192.0.2.99" }).rows[0].likelyForward === false);
check("reporters honour excludeForwards", db.reporters({ excludeForwards: true }).find((r) => r.orgName === "Yahoo") === undefined && db.reporters().length === 3);

check("search: source ip", db.summary({ q: "192.0.2.99" }).totals.messages === 7);
check("search: reverse dns", db.summary({ q: "BADHOST" }).totals.messages === 7 && db.ips({ q: "badhost" }).length === 1);
check("search: spf domain", db.ips({ q: "spammer" }).length === 1 && db.ips({ q: "spammer" })[0].ip === "198.51.100.7");
check("search: envelope from", db.records({ q: "forwarder.test" }).total === 2);
check("search: reporter name on reports and records", db.reports({ q: "google" }).total === 1 && db.reporters({ q: "google" }).length === 1);
check("search: reports match through their records (ptr)", db.reports({ q: "badhost" }).total === 1 && db.reports({ q: "badhost" }).rows[0].orgName === "Enterprise Outlook");
check("search: report id", db.reports({ q: "y-1" }).total === 1);
check("search: like wildcards are literal", db.summary({ q: "%" }).totals.messages === 0 && db.summary({ q: "_" }).totals.messages === 0);
check("search: no match", db.summary({ q: "nothing-here" }).totals.messages === 0 && db.reports({ q: "nothing-here" }).total === 0);
check("search combines with excludeForwards", db.summary({ q: "10.10.10.10", excludeForwards: true }).totals.messages === 0);

// --- runs / settings / stats ------------------------------------------------

const runId = db.startRun("manual", 1758000000);
db.finishRun(runId, { messagesSeen: 2, reportsAdded: 2, duplicates: 1, errors: 0 });
const last = db.lastRun();
check("sync run recorded", last.id === runId && last.reports_added === 2 && last.finished_at >= last.started_at && last.since === 1758000000);
check("runs list", db.runs().length === 1);

db.setSetting("cursor", "123");
check("settings", db.getSetting("cursor") === "123" && db.getSetting("missing") === null);

const st = db.stats();
check("stats", st.messages.total === 3 && st.reports.reports === 3 && st.reports.messages === 58);

db.recordMessage({ graphId: "m1", receivedAt: 1758300000, status: "error", error: "boom" });
check("message upsert updates status", db.messagesWithErrors()[0].graph_id === "m1");

db.close();

// --- migration from schema version 1 ---------------------------------------

const os = require("os");
const Database = require("better-sqlite3");
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-migrate-"));
const v1 = new Database(path.join(tmpDir, "dmarc.sqlite"));
v1.exec(`
  CREATE TABLE messages (graph_id TEXT PRIMARY KEY, internet_message_id TEXT, received_at INTEGER NOT NULL, subject TEXT, from_addr TEXT, status TEXT NOT NULL, error TEXT, processed_at INTEGER NOT NULL);
  CREATE TABLE reports (id INTEGER PRIMARY KEY, message_id TEXT, org_name TEXT NOT NULL, org_email TEXT, report_id TEXT NOT NULL, range_begin INTEGER NOT NULL, range_end INTEGER NOT NULL, domain TEXT NOT NULL, adkim TEXT, aspf TEXT, p TEXT, sp TEXT, pct INTEGER, fo TEXT, messages INTEGER NOT NULL DEFAULT 0, passed INTEGER NOT NULL DEFAULT 0, attachment_name TEXT, xml_gz BLOB, ingested_at INTEGER NOT NULL, UNIQUE(org_name, report_id, domain));
  CREATE TABLE records (id INTEGER PRIMARY KEY, report_id INTEGER NOT NULL, source_ip TEXT NOT NULL, count INTEGER NOT NULL, disposition TEXT NOT NULL, dkim_eval TEXT, spf_eval TEXT, passed INTEGER NOT NULL, reasons TEXT, envelope_to TEXT, envelope_from TEXT, header_from TEXT, dkim_results TEXT, spf_results TEXT, dkim_domain TEXT, spf_domain TEXT);
  INSERT INTO reports (id, org_name, report_id, range_begin, range_end, domain, messages, passed, ingested_at) VALUES (1, 'x', '1', 1, 2, 'example.com', 3, 0, 1);
  INSERT INTO records (report_id, source_ip, count, disposition, passed, reasons, header_from, dkim_results) VALUES
    (1, '10.0.0.1', 1, 'none', 0, '[{"type":"forwarded","comment":null}]', 'example.com', '[]'),
    (1, '10.0.0.2', 1, 'none', 0, '[]', 'example.com', '[{"domain":"example.com","selector":"s","result":"fail","humanResult":null}]'),
    (1, '10.0.0.3', 1, 'none', 0, '[]', 'example.com', '[]');
  PRAGMA user_version = 1;
`);
v1.close();

const migrated = openDatabase({ dataDir: tmpDir });
check("migration: schema version bumped", migrated.db.pragma("user_version", { simple: true }) === 2);
check("migration: forwarded column added", migrated.db.pragma("table_info(records)").some((c) => c.name === "forwarded"));
const flags = Object.fromEntries(migrated.db.prepare("SELECT source_ip, forwarded FROM records").all().map((r) => [r.source_ip, r.forwarded]));
check("migration: existing failures re-derived", flags["10.0.0.1"] === 1 && flags["10.0.0.2"] === 1 && flags["10.0.0.3"] === 0, JSON.stringify(flags));
check("migration: queries work on migrated db", migrated.summary().totals.likelyForwards === 2);
migrated.close();
fs.rmSync(tmpDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });

process.exit(report() ? 0 : 1);
