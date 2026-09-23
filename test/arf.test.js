/** ARF (forensic report) parsing: MIME structure, encodings, field extraction. */
const fs = require("fs");
const path = require("path");
const { createChecker } = require("./helpers/assert");
const arf = require("../arf-parser");

const { check, report } = createChecker("ARF: MIME reader and forensic report fields");
const eml = fs.readFileSync(path.join(__dirname, "..", "examples", "forensic-report.eml"));

// --- MIME reader ---------------------------------------------------------------
const root = arf.parseMime(eml);
check("multipart/report parsed into three parts", root.contentType.type === "multipart/report" && root.contentType.params["report-type"] === "feedback-report" && root.parts.length === 3);
check("part types", root.parts.map((p) => p.contentType.type).join(",") === "text/plain,message/feedback-report,message/rfc822");
check("base64 part decoded", /^Received: from vps.example.net/.test(root.parts[2].body));
check("folded header joined", arf.splitHeaders("A: one\n two\nB: x\n\nbody").headers[0][1] === "one two");
check("content-type params with quotes", arf.parseContentType('multipart/mixed; boundary="a b"; charset=utf-8').params.boundary === "a b");
check("encoded words: base64 and Q", arf.decodeHeaderWords("=?utf-8?B?SGVsbG8=?= =?utf-8?Q?w=C3=B6rld_x?=") === "Hello wörld x");

// --- ARF fields ----------------------------------------------------------------
const f = arf.parseArf(eml);
check("feedback fields", f.feedbackType === "auth-failure" && f.authFailure === "dmarc" && f.sourceIp === "185.220.101.7" && f.reportedDomain === "example.com" && f.deliveryResult === "spam");
check("arrival date parsed", f.arrivalAt === Date.parse("Tue, 22 Sep 2026 09:30:44 +0000") / 1000);
check("envelope addresses bare and lower-cased", f.originalMailFrom === "bounce@spammy.example.net" && f.originalRcptTo === "someone@receiver.test");
check("authentication results kept, folded", /dmarc=fail/.test(f.authenticationResults) && /dkim=none/.test(f.authenticationResults));
check("reporting mta", f.reportingMta === "dns; mx.receiver.test" && f.reporterFrom === "dmarc-noreply@receiver.test");
check("original message headers", f.originalFrom === "\"Accounts Payable\" <finance@example.com>" && f.originalTo === "someone@receiver.test" && f.originalMessageId === "<20260922093012.12345@vps.example.net>");
check("original subject decoded from encoded word", f.originalSubject === "Urgent invoice – pay today");
check("original date", f.originalDate === Date.parse("Tue, 22 Sep 2026 09:30:12 +0000") / 1000);
check("headers text captured without the body", /^Received:/.test(f.headers) && !/Please pay/.test(f.headers) && f.headers.length < 8192);

// --- variants -------------------------------------------------------------------
const qp = eml.toString()
  .replace("Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64", "Content-Type: text/rfc822-headers\r\nContent-Transfer-Encoding: quoted-printable")
  // In a quoted-printable body every "=" is written "=3D", so an encoded word in a header looks like this on the wire.
  .replace(/\r\n\r\n[A-Za-z0-9+/=\r\n]+\r\n--arf-boundary--/, "\r\n\r\nFrom: =3D?utf-8?Q?J=3DC3=3DBCrgen?=3D <j@example.com>\r\nSubject: caf=C3=A9 order\r\nMessage-ID: <qp@x>\r\n\r\n--arf-boundary--");
const g = arf.parseArf(qp);
check("text/rfc822-headers with quoted-printable", g.originalSubject === "café order" && g.originalFrom === "Jürgen <j@example.com>" && g.originalMessageId === "<qp@x>");
check("arrival date falls back to the report date when only headers are present", g.arrivalAt === Date.parse("Tue, 22 Sep 2026 09:30:44 +0000") / 1000);

const noFeedback = eml.toString().replace("Content-Type: message/feedback-report", "Content-Type: text/plain");
let threw = null;
try { arf.parseArf(noFeedback); } catch (e) { threw = e; }
check("no feedback-report part is NotArfError", threw && threw.code === "not_arf");

const noOriginal = eml.toString().slice(0, eml.toString().indexOf("--arf-boundary\r\nContent-Type: message/rfc822")) + "--arf-boundary--\r\n";
const h = arf.parseArf(noOriginal);
check("report without the original message still parses", h.sourceIp === "185.220.101.7" && h.originalFrom === null && h.headers === null && h.arrivalAt > 0);

check("looksLikeArf: subject hints", arf.looksLikeArf({ subject: "DMARC failure report" }) && arf.looksLikeArf({ subject: "Forensic report for example.com" }) && !arf.looksLikeArf({ subject: "Report domain: example.com Submitter: google.com aggregate" }) && !arf.looksLikeArf({ subject: "Lunch?" }));
check("looksLikeArf: attachment content type", arf.looksLikeArf({ subject: "x", attachments: [{ contentType: "message/feedback-report" }] }));

process.exit(report() ? 0 : 1);
