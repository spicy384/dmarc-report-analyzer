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

// --- runs / settings / stats ------------------------------------------------

const runId = db.startRun("manual", 1758000000);
db.finishRun(runId, { messagesSeen: 2, reportsAdded: 2, duplicates: 1, errors: 0 });
const last = db.lastRun();
check("sync run recorded", last.id === runId && last.reports_added === 2 && last.finished_at >= last.started_at && last.since === 1758000000);
check("runs list", db.runs().length === 1);

db.setSetting("cursor", "123");
check("settings", db.getSetting("cursor") === "123" && db.getSetting("missing") === null);

const st = db.stats();
check("stats", st.messages.total === 2 && st.reports.reports === 2 && st.reports.messages === 53);

db.recordMessage({ graphId: "m1", receivedAt: 1758300000, status: "error", error: "boom" });
check("message upsert updates status", db.messagesWithErrors()[0].graph_id === "m1");

db.close();
process.exit(report() ? 0 : 1);
