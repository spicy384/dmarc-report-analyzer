/** Unit tests for dmarc-parser.js against the sample reports in examples/. */
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const { zipSync } = require("fflate");

const { createChecker } = require("./helpers/assert");
const parser = require("../dmarc-parser");

const { check, report } = createChecker("Parser: containers and aggregate XML");
const EX = path.join(__dirname, "..", "examples");
const googleXml = fs.readFileSync(path.join(EX, "google-aggregate.xml"));
const microsoftXml = fs.readFileSync(path.join(EX, "microsoft-aggregate.xml"));

// --- container detection ----------------------------------------------------

const bare = parser.extractXmlDocuments(googleXml, "google.com!example.com!1758153600!1758239999.xml");
check("bare xml yields one document", bare.length === 1 && bare[0].xml.includes("<feedback>"));

const gz = zlib.gzipSync(microsoftXml);
const fromGz = parser.extractXmlDocuments(gz, "report.xml.gz");
check("gzip is unpacked", fromGz.length === 1 && fromGz[0].name === "report.xml");

const zipped = Buffer.from(zipSync({ "google.com!example.com!1.xml": new Uint8Array(googleXml) }));
const fromZip = parser.extractXmlDocuments(zipped, "misnamed.dat");
check("zip is unpacked regardless of filename", fromZip.length === 1 && fromZip[0].name.endsWith(".xml"));

const zipOfGz = Buffer.from(zipSync({ "inner.xml.gz": new Uint8Array(gz), "folder/": new Uint8Array(0) }));
const nested = parser.extractXmlDocuments(zipOfGz, "nested.zip");
check("zip containing gzip is unpacked, directory entries skipped", nested.length === 1);

const bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("\n  "), googleXml]);
check("BOM and leading whitespace are tolerated", parser.extractXmlDocuments(bom).length === 1);

check("a PNG is not a report", parser.extractXmlDocuments(Buffer.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3])).length === 0);
check("empty bytes are not a report", parser.extractXmlDocuments(Buffer.alloc(0)).length === 0);

// --- aggregate parsing ------------------------------------------------------

const g = parser.parseAggregateReport(googleXml.toString());
check("google: org name", g.metadata.orgName === "google.com");
check("google: report id", g.metadata.reportId === "12345678901234567890");
check("google: date range", g.metadata.dateRange.begin === 1758153600 && g.metadata.dateRange.end === 1758239999);
check("google: policy", g.policy.domain === "example.com" && g.policy.p === "quarantine" && g.policy.pct === 100);
check("google: two records", g.records.length === 2);
check("google: passing record", g.records[0].sourceIp === "203.0.113.10" && g.records[0].count === 42 && g.records[0].passed === true);
check("google: dkim selector kept", g.records[0].dkimResults[0].selector === "selector1");
check("google: failing record", g.records[1].passed === false && g.records[1].disposition === "quarantine");
check("google: spf domain from auth_results", g.records[1].spfDomain === "mail.spammer.test" && g.records[1].dkimDomain === null);
check("google: envelope fields null when absent", g.records[1].envelopeFrom === null && g.records[1].headerFrom === "example.com");

const totals = parser.summarizeRecords(g.records);
check("google: totals", totals.messages === 45 && totals.passed === 42 && totals.failed === 3);

const m = parser.parseAggregateReport(microsoftXml.toString());
check("microsoft: namespaced root parsed", m.metadata.orgName === "Enterprise Outlook");
check("microsoft: fo kept", m.policy.fo === "0");
check("microsoft: ipv6 source", m.records[0].sourceIp === "2001:db8::25");
check("microsoft: dkim pass + spf fail = DMARC pass", m.records[0].passed === true && m.records[0].spfEval === "fail");
check("microsoft: single reason wrapped as array", m.records[0].reasons.length === 1 && m.records[0].reasons[0].type === "forwarded");
check("microsoft: multiple dkim results", m.records[0].dkimResults.length === 2 && m.records[0].dkimDomain === "example.com");
check("microsoft: spf scope", m.records[0].spfResults[0].scope === "mfrom");
check("microsoft: envelope identifiers", m.records[0].envelopeTo === "contoso.test" && m.records[0].envelopeFrom === "forwarder.test");
check("microsoft: two reasons, reject", m.records[1].reasons.length === 2 && m.records[1].disposition === "reject");
check("microsoft: softfail is not a pass", m.records[1].passed === false);

// --- edge cases -------------------------------------------------------------

const single = `<feedback><report_metadata><org_name>x</org_name><report_id>1</report_id>
<date_range><begin>1</begin><end>2</end></date_range></report_metadata>
<policy_published><domain>EXAMPLE.ORG</domain></policy_published>
<record><row><source_ip>10.0.0.1</source_ip><policy_evaluated><dkim>PASS</dkim></policy_evaluated></row></record></feedback>`;
const s = parser.parseAggregateReport(single);
check("single record is still an array", Array.isArray(s.records) && s.records.length === 1);
check("count defaults to 1, disposition to none", s.records[0].count === 1 && s.records[0].disposition === "none");
check("domain and enums lower-cased", s.policy.domain === "example.org" && s.records[0].dkimEval === "pass");
check("pct defaults to 100", s.policy.pct === 100);

let threw = null;
try { parser.parseAggregateReport("<html><body>hi</body></html>"); } catch (e) { threw = e; }
check("html raises NotAReportError", threw && threw.code === "not_a_report");

threw = null;
try { parser.parseAggregateReport("<feedback><record></record></feedback>"); } catch (e) { threw = e; }
check("feedback without metadata raises a plain error", threw && threw.code !== "not_a_report" && /report_metadata/.test(threw.message));

threw = null;
try { parser.parseAggregateReport("<feedback><report_metadata><org_name>x"); } catch (e) { threw = e; }
check("truncated xml raises", Boolean(threw));

threw = null;
try { parser.extractXmlDocuments(Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00]), "bad.gz"); } catch (e) { threw = e; }
check("corrupt gzip raises", Boolean(threw));

process.exit(report() ? 0 : 1);
