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

// --- geoip cache ------------------------------------------------------------
check("ips missing geo: every source at first", db.ipsMissingGeo().length === 5);
db.setGeo("192.0.2.99", { countryCode: "DE", country: "Germany", city: "Berlin", asn: 3320, asOrg: "Deutsche Telekom AG", source: "online" });
db.setGeo("203.0.113.10", { source: "none" });
check("geo stored and joined onto ips", db.ips().find((r) => r.ip === "192.0.2.99").countryCode === "DE" && db.ips().find((r) => r.ip === "192.0.2.99").asOrg === "Deutsche Telekom AG" && db.ips().find((r) => r.ip === "192.0.2.99").ptr === "mail.badhost.test");
check("geo miss cached as none", db.ipsMissingGeo().length === 3 && db.geoStats().unknown === 1 && db.geoStats().fromOnline === 1);
check("records expose geo", db.records({}, { ip: "192.0.2.99" }).rows[0].asOrg === "Deutsche Telekom AG");
check("search matches network and country", db.summary({ q: "telekom" }).totals.messages === 7 && db.summary({ q: "germany" }).totals.messages === 7 && db.reports({ q: "telekom" }).total === 1);
check("clearGeo forgets answers", db.clearGeo() === 2 && db.ipsMissingGeo().length === 5);
db.setGeo("192.0.2.99", { countryCode: "DE", country: "Germany", asn: 3320, asOrg: "Deutsche Telekom AG", source: "online" });

// --- forensic reports -------------------------------------------------------
const { parseArf } = require("../arf-parser");
const arfParsed = parseArf(fs.readFileSync(path.join(EX, "forensic-report.eml")));
check("no forensic reports yet", db.forensicCount() === 0 && db.forensics().total === 0);
const fr = db.insertForensic({ messageId: "arf-1", mailboxId: "env", parsed: arfParsed });
check("forensic inserted", fr.id > 0 && !fr.duplicate && db.forensicCount() === 1);
check("forensic duplicate by message id ignored", db.insertForensic({ messageId: "arf-1", parsed: arfParsed }).duplicate === true);
const flist = db.forensics();
check("forensic list joined with ip_info", flist.total === 1 && flist.rows[0].sourceIp === "185.220.101.7" && flist.rows[0].originalSubject === "Urgent invoice – pay today" && flist.rows[0].headers === undefined);
check("forensic by id carries headers", /^Received:/.test(db.forensicById(fr.id).headers) && db.forensicById(999) === null);
check("forensic filters: window, domain, ip, search", db.forensics({ from: arfParsed.arrivalAt + 1 }).total === 0 && db.forensics({ domain: "example.com" }).total === 1 && db.forensics({}, { ip: "1.2.3.4" }).total === 0 && db.forensics({ q: "invoice" }).total === 1 && db.forensics({ q: "spammy" }).total === 1 && db.forensics({ q: "nothing" }).total === 0);

// --- first-seen sources -----------------------------------------------------
const fresh = db.firstSeenSources({ from: 1758153600, to: 1758240000 });
check("first-seen sources inside the window", fresh.length === 5 && fresh[0].failed >= fresh[fresh.length - 1].failed && fresh.find((r) => r.ip === "192.0.2.99").ptr === "mail.badhost.test");
check("first-seen sources outside the window", db.firstSeenSources({ from: 1758240000, to: 1758326400 }).length === 0);
check("first-seen honours the domain filter", db.firstSeenSources({ from: 1758153600, to: 1758240000, domain: "nope.test" }).length === 0);

// --- dkim selectors ---------------------------------------------------------
const sels = db.dkimSelectors("example.com");
check("dkim selectors seen for the domain (including the forwarder's)", sels.length === 3 && sels.find((s) => s.selector === "selector1").passed === 42 && sels.find((s) => s.selector === "s1").signingDomain === "example.com" && sels.find((s) => s.selector === "fwd").signingDomain === "forwarder.test", JSON.stringify(sels));
check("dkim selectors: other domain empty", db.dkimSelectors("nope.test").length === 0);

// --- known senders ----------------------------------------------------------
check("no known senders yet", db.knownSenders().length === 0 && db.ips().every((r) => r.sender === null));
const ks1 = db.addKnownSender({ pattern: "203.0.113.0/24", kind: "ours", label: "Our mail server" }, { createdBy: "admin" });
check("known sender added", ks1.id > 0 && ks1.pattern === "203.0.113.0/24" && ks1.source === "manual" && ks1.created_by === "admin");
const ks2 = db.addKnownSender({ pattern: "*.badhost.test", kind: "other", label: "Known bad host", note: " seen before " });
check("hostname pattern added with trimmed note", ks2.kind === "other" && ks2.note === "seen before");
const bad = (f) => { try { db.addKnownSender(f); return null; } catch (e) { return e.status; } };
check("validation: pattern", bad({ pattern: "nope nope", kind: "ours", label: "x" }) === 400);
check("validation: kind", bad({ pattern: "10.0.0.1", kind: "friend", label: "x" }) === 400);
check("validation: label", bad({ pattern: "10.0.0.1", kind: "ours", label: "" }) === 400);
check("duplicate pattern is 409", bad({ pattern: "203.0.113.0/24", kind: "vendor", label: "dup" }) === 409);
check("ips carry their sender", db.ips().find((r) => r.ip === "203.0.113.10").sender.label === "Our mail server" && db.ips().find((r) => r.ip === "192.0.2.99").sender.kind === "other" && db.ips().find((r) => r.ip === "198.51.100.7").sender === null);
const bs = db.summary().bySender;
check("summary bySender", bs.ours.total === 42 && bs.ours.failed === 0 && bs.other.failed === 7 && bs.unknown.failed === 8 && bs.unknown.sources === 3, JSON.stringify(bs));
const ksUpd = db.updateKnownSender(ks2.id, { kind: "vendor", label: "Now a vendor" });
check("update known sender", ksUpd.kind === "vendor" && db.summary().bySender.vendor.failed === 7);
check("update unknown id is 404", (() => { try { db.updateKnownSender(999, { label: "x" }); return false; } catch (e) { return e.status === 404; } })());
db.removeKnownSender(ks2.id);
check("remove known sender", db.knownSenders().length === 1 && db.ips().find((r) => r.ip === "192.0.2.99").sender === null);
check("remove unknown id is 404", (() => { try { db.removeKnownSender(999); return false; } catch (e) { return e.status === 404; } })());

// --- mailboxes --------------------------------------------------------------
check("rows default to the env mailbox", db.summary({ mailbox: "env" }).totals.messages === 58 && db.summary({ mailbox: "other" }).totals.messages === 0);
db.recordMessage({ graphId: "m5", mailboxId: "box2", receivedAt: 1758340000, subject: "other box", fromAddr: "x@y.z", status: "ingested" });
const other = db.insertReport({ messageId: "m5", mailboxId: "box2", attachmentName: "o.xml", parsed: parseAggregateReport(googleXml.replace("<report_id>12345678901234567890</report_id>", "<report_id>box2-1</report_id>")), xml: googleXml });
check("report stored under its mailbox", !other.duplicate && db.reports({ mailbox: "box2" }).rows[0].mailboxId === "box2" && db.reports({ mailbox: "box2" }).total === 1);
check("mailbox filter isolates totals", db.summary({ mailbox: "box2" }).totals.messages === 45 && db.summary().totals.messages === 103);
check("latest received per mailbox", db.latestMessageReceivedAt("box2") === 1758340000 && db.latestMessageReceivedAt("env") === 1758330000 && db.latestMessageReceivedAt() === 1758340000);
check("mailbox counts", db.mailboxCounts().length === 2 && db.mailboxCounts().find((c) => c.id === "box2").messages === 45);

// --- runs / settings / stats ------------------------------------------------

const runId = db.startRun("manual", 1758000000);
db.finishRun(runId, { messagesSeen: 2, reportsAdded: 2, duplicates: 1, errors: 0 });
const last = db.lastRun();
check("sync run recorded", last.id === runId && last.reports_added === 2 && last.finished_at >= last.started_at && last.since === 1758000000);
check("runs list", db.runs().length === 1);
for (let i = 0; i < 5; i += 1) db.finishRun(db.startRun("scheduled", null, "env"), {});
db.finishRun(db.startRun("scheduled", null, "box2"), {});
check("pruneRuns keeps the newest runs of each mailbox", db.pruneRuns({ keepPerMailbox: 3 }) === 3 && db.runs().length === 4 && db.runs().filter((r) => r.mailbox_id === "env").length === 3 && db.lastRunsByMailbox().length === 2);


const geoFirst = openDatabase({ file: ":memory:" });
geoFirst.insertReport({ messageId: "g1", attachmentName: "g.xml", parsed: parseAggregateReport(googleXml), xml: googleXml });
geoFirst.setGeo("203.0.113.10", { source: "none" });
check("a geo lookup alone leaves the reverse lookup pending", geoFirst.ipsMissingPtr().includes("203.0.113.10"));
geoFirst.setPtr("203.0.113.10", null);
check("a reverse lookup with no answer is still done", !geoFirst.ipsMissingPtr().includes("203.0.113.10") && geoFirst.ips().find((r) => r.ip === "203.0.113.10").ptr === null);

db.setSetting("cursor", "123");
check("settings", db.getSetting("cursor") === "123" && db.getSetting("missing") === null);

const st = db.stats();
check("stats", st.messages.total === 4 && st.reports.reports === 4 && st.reports.messages === 103);
db.recordMessage({ graphId: "ff1", mailboxId: "env", receivedAt: 1758000000, status: "fetch_failed", error: "socket hang up" });
check("a failed download is not a seen message but is listed with the errors", !db.hasMessage("ff1") && db.messagesWithErrors().some((m) => m.graph_id === "ff1"));
check("oldest failed download within a window", db.oldestFailedMessageAt("env", 1757000000) === 1758000000 && db.oldestFailedMessageAt(null, 1757000000) === 1758000000 && db.oldestFailedMessageAt("env", 1759000000) === null && db.oldestFailedMessageAt("box2", 0) === null);
db.recordMessage({ graphId: "ff1", mailboxId: "env", receivedAt: 1758000000, status: "no_report", error: null });
check("a later success replaces the failed download", db.hasMessage("ff1") && db.oldestFailedMessageAt("env", 0) === null);

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
check("migration: schema version bumped", migrated.db.pragma("user_version", { simple: true }) >= 4);
check("migration: known_senders table exists", migrated.knownSenders().length === 0);
check("migration: mailbox columns added and backfilled", migrated.db.prepare("SELECT COUNT(*) AS n FROM reports WHERE mailbox_id = 'env'").get().n === 1 && migrated.reports({ mailbox: "env" }).total === 1);
check("migration: forwarded column added", migrated.db.pragma("table_info(records)").some((c) => c.name === "forwarded"));
const flags = Object.fromEntries(migrated.db.prepare("SELECT source_ip, forwarded FROM records").all().map((r) => [r.source_ip, r.forwarded]));
check("migration: existing failures re-derived", flags["10.0.0.1"] === 1 && flags["10.0.0.2"] === 1 && flags["10.0.0.3"] === 0, JSON.stringify(flags));
check("migration: queries work on migrated db", migrated.summary().totals.likelyForwards === 2);
migrated.close();
fs.rmSync(tmpDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });

// --- subdomains -------------------------------------------------------------------
{
  const sub = openDatabase({ file: ":memory:" });
  const parsed = parseAggregateReport(googleXml);
  parsed.metadata.reportId = "sub-1";
  parsed.policy.sp = null;
  parsed.policy.p = "quarantine";
  // A passing parent, an in-use subdomain, and a subdomain that only ever fails.
  parsed.records = [
    { ...parsed.records[0], headerFrom: "example.com", count: 100, passed: true, sourceIp: "198.51.100.1" },
    { ...parsed.records[0], headerFrom: "news.example.com", count: 40, passed: true, sourceIp: "198.51.100.2" },
    { ...parsed.records[0], headerFrom: "news.example.com", count: 10, passed: false, disposition: "none", sourceIp: "203.0.113.5" },
    { ...parsed.records[0], headerFrom: "hr.example.com", count: 25, passed: false, disposition: "none", sourceIp: "203.0.113.9" },
    { ...parsed.records[0], headerFrom: "other.test", count: 3, passed: false, disposition: "none", sourceIp: "203.0.113.10" }
  ];
  sub.insertReport({ messageId: "s1", attachmentName: "s.xml", parsed, xml: googleXml });
  const rows = sub.subdomains({});
  const byDomain = Object.fromEntries(rows.map((r) => [r.domain, r]));
  check("subdomains: one row per From domain, biggest first", rows.length === 4 && rows[0].domain === "example.com");
  check("subdomains: parent recognised with p=", byDomain["example.com"].relation === "parent" && byDomain["example.com"].appliedPolicy === "quarantine" && byDomain["example.com"].unused === false);
  check("subdomains: in-use subdomain inherits p= when sp= is absent", byDomain["news.example.com"].relation === "subdomain" && byDomain["news.example.com"].passed === 40 && byDomain["news.example.com"].failed === 10 && byDomain["news.example.com"].inheritsPolicy === true && byDomain["news.example.com"].appliedPolicy === "quarantine" && byDomain["news.example.com"].unused === false);
  check("subdomains: failure-only subdomain flagged as unused", byDomain["hr.example.com"].unused === true && byDomain["hr.example.com"].failPct === 100 && byDomain["hr.example.com"].failingSources === 1);
  check("subdomains: a From domain outside the report domain is 'other'", byDomain["other.test"].relation === "other");
  const parsed2 = parseAggregateReport(googleXml);
  parsed2.metadata.reportId = "sub-2";
  parsed2.policy.sp = "reject";
  parsed2.records = [{ ...parsed2.records[0], headerFrom: "hr.example.com", count: 5, passed: false, disposition: "reject", sourceIp: "203.0.113.9" }];
  sub.insertReport({ messageId: "s2", attachmentName: "s2.xml", parsed: parsed2, xml: googleXml });
  const later = Object.fromEntries(sub.subdomains({}).map((r) => [r.domain, r]));
  check("subdomains: the newest report's sp= applies to subdomains", later["hr.example.com"].appliedPolicy === "reject" && later["hr.example.com"].inheritsPolicy === false && later["hr.example.com"].total === 30);
  // An older report that arrives later (higher id, earlier window) must not be taken for the current policy.
  const parsed3 = parseAggregateReport(googleXml);
  parsed3.metadata.reportId = "sub-3-old";
  parsed3.metadata.dateRange = { begin: parsed3.metadata.dateRange.begin - 10 * 86400, end: parsed3.metadata.dateRange.end - 10 * 86400 };
  parsed3.policy.sp = "none";
  parsed3.records = [];
  sub.insertReport({ messageId: "s3", attachmentName: "s3.xml", parsed: parsed3, xml: googleXml });
  check("subdomains: the policy comes from the newest window, not the newest row", Object.fromEntries(sub.subdomains({}).map((r) => [r.domain, r]))["hr.example.com"].appliedPolicy === "reject");
  check("subdomains: search filter narrows to a From domain", sub.subdomains({ q: "hr.example.com" }).every((r) => r.domain === "hr.example.com"));

  // --- scorecard on the same data: one domain, quarantine, a spoofed subdomain, unlabelled failing sources ---
  const card = sub.scorecard({}, { now: parsed2.metadata.dateRange.end + 2 * 86400 });
  check("scorecard: one row per report domain with volumes", card.length === 1 && card[0].domain === "example.com" && card[0].total === 183 && card[0].passed === 140 && card[0].reports === 2);
  check("scorecard: the newest report's policy", card[0].policy.p === "quarantine" && card[0].policy.sp === "reject");
  check("scorecard: counts unlabelled failing sources and spoofed subdomains", card[0].unlabelledFailingSources === 3 && card[0].unusedSubdomains === 1, JSON.stringify(card[0]));
  check("scorecard: warn with the reasons spelled out", card[0].status === "warn" && card[0].issues.some((i) => /3 failing sources without a label/.test(i)) && !card[0].issues.some((i) => /spoofed subdomain/.test(i)), JSON.stringify(card[0].issues));
  sub.addKnownSender({ pattern: "203.0.113.0/24", kind: "ours", label: "Office" }, { createdBy: "t", source: "manual" });
  const labelled = sub.scorecard({}, { now: parsed2.metadata.dateRange.end + 2 * 86400 })[0];
  check("scorecard: labelling the sources clears that issue", labelled.unlabelledFailingSources === 0 && !labelled.issues.some((i) => /without a label/.test(i)));
  const silent = sub.scorecard({}, { now: parsed2.metadata.dateRange.end + 30 * 86400 })[0];
  check("scorecard: a domain that stopped reporting is flagged", silent.silentDays >= 29 && silent.issues.some((i) => /no report for \d+ days/.test(i)));
  const none = openDatabase({ file: ":memory:" });
  const parsedNone = parseAggregateReport(googleXml);
  parsedNone.policy.p = "none";
  none.insertReport({ messageId: "n1", attachmentName: "n.xml", parsed: parsedNone, xml: googleXml });
  check("scorecard: p=none is critical", none.scorecard({}, { now: parsedNone.metadata.dateRange.end + 86400 })[0].status === "critical");
  none.close();
  sub.close();
}

process.exit(report() ? 0 : 1);
