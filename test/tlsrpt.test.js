/** TLS-RPT (RFC 8460) parsing and the shared ingest path for uploads and attachments. */
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const { zipSync } = require("fflate");
const { createChecker } = require("./helpers/assert");
const { extractJsonDocuments, parseTlsReport, describeResultType, NotATlsReportError } = require("../tlsrpt-parser");
const { openDatabase } = require("../db");
const { createIngest, looksLikeEmail } = require("../ingest");

const { check, report } = createChecker("TLS-RPT parser and shared ingest");
const EX = path.join(__dirname, "..", "examples");
const exampleJson = fs.readFileSync(path.join(EX, "tls-report.json"), "utf8");

// --- parser ----------------------------------------------------------------------
const r = parseTlsReport(exampleJson);
check("report metadata", r.orgName === "Company-X" && r.reportId === "5065427c-23d3-47ca-b6e0-946ea0e8c4be" && r.contactInfo === "sts-reporting@company-x.example");
check("window in unix seconds", r.rangeBegin === Date.parse("2026-09-28T00:00:00Z") / 1000 && r.rangeEnd === Date.parse("2026-09-28T23:59:59Z") / 1000);
check("one policy with totals", r.policies.length === 1 && r.policies[0].policyType === "sts" && r.policies[0].policyDomain === "example.com" && r.policies[0].successful === 5326 && r.policies[0].failed === 303);
check("policy string and mx kept", r.policies[0].policyString.length === 4 && r.policies[0].mxHosts[0] === "*.mail.example.com");
const f = r.policies[0].failures;
check("failure details normalised", f.length === 3 && f[0].resultType === "certificate-expired" && f[0].sendingMtaIp === "2001:db8:abcd:0012::1" && f[0].receivingMxHostname === "mx1.mail.example.com" && f[0].failedSessionCount === 100);
check("optional failure fields", f[1].receivingIp === "203.0.113.56" && f[1].additionalInformation.startsWith("https://") && f[2].failureReasonCode === "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED");
check("failed total falls back to the sum of failures", parseTlsReport({ "organization-name": "x", "date-range": { "start-datetime": "2026-01-01T00:00:00Z", "end-datetime": "2026-01-01T23:59:59Z" }, policies: [{ policy: { "policy-type": "no-policy-found", "policy-domain": "a.test" }, summary: { "total-successful-session-count": 1 }, "failure-details": [{ "result-type": "starttls-not-supported", "failed-session-count": 7 }] }] }).policies[0].failed === 7);
check("missing report-id is synthesised", parseTlsReport({ "organization-name": "x", "date-range": { "start-datetime": "2026-01-01T00:00:00Z", "end-datetime": "2026-01-01T23:59:59Z" }, policies: [{ policy: {}, summary: {} }] }).reportId === "x-1767225600-1767311999");
let threw = null;
try { parseTlsReport('{"hello":"world"}'); } catch (e) { threw = e; }
check("other JSON is not-a-report", threw instanceof NotATlsReportError && threw.code === "not_a_report");
threw = null;
try { parseTlsReport("{nope"); } catch (e) { threw = e; }
check("broken JSON is an ordinary error", threw && !(threw instanceof NotATlsReportError) && /not valid JSON/.test(threw.message));
threw = null;
try { parseTlsReport({ "organization-name": "x", "date-range": {}, policies: [] }); } catch (e) { threw = e; }
check("missing date range is an error", threw && /date-range/.test(threw.message));
check("result types have meanings", describeResultType("certificate-expired").includes("expired") && describeResultType("whatever").includes("unlisted"));

// --- containers ------------------------------------------------------------------
const plain = Buffer.from(exampleJson, "utf8");
const gz = zlib.gzipSync(plain);
const zipped = Buffer.from(zipSync({ "company-x!example.com!1759017600!1759103999.json": new Uint8Array(plain), "readme.txt": new Uint8Array(Buffer.from("not json")) }));
check("plain JSON", extractJsonDocuments(plain, "r.json").length === 1);
check("gzip, name unwrapped", extractJsonDocuments(gz, "r.json.gz")[0].name === "r.json" && JSON.parse(extractJsonDocuments(gz, "r.json.gz")[0].json)["report-id"] === r.reportId);
check("zip picks the JSON entries", extractJsonDocuments(zipped, "r.zip").length === 1);
check("XML is not JSON", extractJsonDocuments(Buffer.from("<feedback/>"), "r.xml").length === 0);
check("BOM tolerated", extractJsonDocuments(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), plain]), "r.json").length === 1);

// --- shared ingest: TLS, aggregate, email, junk ----------------------------------
const db = openDatabase({ file: ":memory:" });
const ingest = createIngest({ db });
const t1 = ingest.ingestBytes({ bytes: gz, name: "r.json.gz", messageId: "m1", mailboxId: "env" });
check("ingest: TLS report stored", t1.found === 1 && t1.tls.added === 1 && t1.tls.ids.length === 1 && t1.aggregate.added === 0 && t1.problems.length === 0, JSON.stringify(t1));
const t2 = ingest.ingestBytes({ bytes: plain, name: "r.json", messageId: "m2", mailboxId: "env" });
check("ingest: same report again is a duplicate", t2.found === 1 && t2.tls.added === 0 && t2.tls.duplicates === 1);
const xml = fs.readFileSync(path.join(EX, "google-aggregate.xml"));
const a1 = ingest.ingestBytes({ bytes: xml, name: "google.xml", messageId: "m3", mailboxId: "env" });
check("ingest: aggregate XML still works", a1.found === 1 && a1.aggregate.added === 1 && a1.aggregate.ids.length === 1 && a1.tls.added === 0);
const mixed = Buffer.from(zipSync({ "a.xml": new Uint8Array(fs.readFileSync(path.join(EX, "microsoft-aggregate.xml"))), "b.json": new Uint8Array(plain) }));
const m1 = ingest.ingestBytes({ bytes: mixed, name: "mixed.zip", messageId: "m4", mailboxId: "env" });
check("ingest: a zip with both kinds yields both (TLS one a duplicate)", m1.found === 2 && m1.aggregate.added === 1 && m1.tls.duplicates === 1, JSON.stringify(m1));
const junk = ingest.ingestFile({ bytes: Buffer.from("hello there"), name: "notes.txt", messageId: "m5", mailboxId: "upload" });
check("ingest: junk is a problem, not a crash", junk.found === 0 && junk.problems.length === 1 && /not a DMARC aggregate report/.test(junk.problems[0]));
const badJson = ingest.ingestFile({ bytes: Buffer.from("{broken"), name: "x.json", messageId: "m6", mailboxId: "upload" });
check("ingest: broken JSON names the file", badJson.found === 0 && badJson.problems.length === 1 && /x\.json/.test(badJson.problems[0]), JSON.stringify(badJson.problems));

// A forensic .eml and a carrier email with an attachment.
const eml = fs.readFileSync(path.join(EX, "forensic-report.eml"));
check("looksLikeEmail: by name and by content", looksLikeEmail(eml, "x.eml") && looksLikeEmail(eml, "") && !looksLikeEmail(plain, "r.json"));
const fo = ingest.ingestFile({ bytes: eml, name: "forensic.eml", messageId: "m7", mailboxId: "upload" });
check("ingest: forensic email stored", fo.found === 1 && fo.forensic.added === 1 && fo.problems.length === 0, JSON.stringify(fo));
const carrier = Buffer.from([
  "From: reports@sender.test", "To: dmarc@example.com", "Subject: Report Domain: example.com", "MIME-Version: 1.0",
  'Content-Type: multipart/mixed; boundary="b1"', "", "--b1", "Content-Type: text/plain", "", "see attached", "--b1",
  'Content-Type: application/tlsrpt+gzip; name="sender!example.com!1!2.json.gz"', "Content-Transfer-Encoding: base64",
  'Content-Disposition: attachment; filename="sender!example.com!1!2.json.gz"', "", gz.toString("base64"), "--b1--", ""
].join("\r\n"));
const car = ingest.ingestFile({ bytes: carrier, name: "mail.eml", messageId: "m8", mailboxId: "upload" });
check("ingest: email carrying a TLS report attachment", car.found === 1 && car.tls.duplicates === 1 && car.subject === "Report Domain: example.com", JSON.stringify(car));

// --- storage queries ----------------------------------------------------------------
const list = db.tlsReports({});
check("tlsReports: one row with derived fields", list.total === 1 && list.rows[0].policyMode === "testing" && list.rows[0].failureTypes.length === 3 && list.rows[0].policyDomain === "example.com");
const full = db.tlsReportById(list.rows[0].id);
check("tlsReportById: full failures and policy string", full.failures.length === 3 && full.policyString[1] === "mode: testing");
check("tlsReportRaw: JSON round-trips", JSON.parse(db.tlsReportRaw(full.id).json)["report-id"] === r.reportId);
const s = db.tlsSummary({});
check("tlsSummary: totals and breakdowns", s.reports === 1 && s.successful === 5326 && s.failed === 303 && s.testingReports === 1 && s.byType[0].resultType === "starttls-not-supported" && s.byType[0].sessions === 200 && s.byMx.length === 3 && s.bySender.length === 3 && s.days.length === 1, JSON.stringify(s));
check("tlsSummary: domain filter", db.tlsSummary({ domain: "example.com" }).reports === 1 && db.tlsSummary({ domain: "other.test" }).reports === 0);
check("tlsReports: search hits failure text", db.tlsReports({ q: "certificate-expired" }).total === 1 && db.tlsReports({ q: "zzz" }).total === 0);
check("tlsCount", db.tlsCount() === 1);

db.close();
process.exit(report() ? 0 : 1);
