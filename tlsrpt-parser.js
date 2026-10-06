/**
 * SMTP TLS reports (RFC 8460, "TLS-RPT"): a JSON document a receiving domain's
 * MTA-STS/DANE-aware senders mail once a day to the rua= address in
 * `_smtp._tls.<domain>`, saying how many TLS sessions to that domain succeeded
 * and how many failed, and why. Delivered as an attachment named
 * `<sender>!<domain>!<begin>!<end>[!id].json[.gz]` with a tlsrpt+json or
 * tlsrpt+gzip type, which senders mislabel as often as they do DMARC reports,
 * so the container is sniffed from the bytes.
 */
const zlib = require("zlib");
const { unzipSync } = require("fflate");

/** Thrown when bytes are JSON but not a TLS report. */
class NotATlsReportError extends Error {
  constructor(message) {
    super(message);
    this.name = "NotATlsReportError";
    this.code = "not_a_report";
  }
}

const MAX_JSON_BYTES = 20 * 1024 * 1024;
const MAX_CONTAINER_DEPTH = 3;

// RFC 8460 section 4.3; anything else is kept verbatim.
const RESULT_TYPES = new Set([
  "starttls-not-supported", "certificate-host-mismatch", "certificate-expired", "certificate-not-trusted",
  "validation-failure", "tlsa-invalid", "dnssec-invalid", "dane-required",
  "sts-policy-fetch-error", "sts-policy-invalid", "sts-webpki-invalid"
]);
const POLICY_TYPES = new Set(["tlsa", "sts", "no-policy-found"]);

function isGzip(buf) {
  return buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b;
}

function isZip(buf) {
  return buf.length > 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04;
}

/** True when the bytes look like a JSON object: optional BOM and whitespace, then "{". */
function looksLikeJson(buf) {
  let i = 0;
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) i = 3;
  while (i < buf.length && (buf[i] === 0x20 || buf[i] === 0x09 || buf[i] === 0x0a || buf[i] === 0x0d)) i += 1;
  return i < buf.length && buf[i] === 0x7b;
}

/** Unpacks an attachment into the JSON texts it holds: [{ name, json }], empty when it is not JSON. */
function extractJsonDocuments(buffer, filename = "", depth = 0) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  if (depth > MAX_CONTAINER_DEPTH) {
    throw new Error(`${filename || "attachment"}: containers nested too deeply`);
  }
  if (isGzip(buf)) {
    const inner = zlib.gunzipSync(buf, { maxOutputLength: MAX_JSON_BYTES });
    return extractJsonDocuments(inner, filename.replace(/\.gz$/i, "") || "report.json", depth + 1);
  }
  if (isZip(buf)) {
    const entries = unzipSync(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
    const docs = [];
    for (const [name, bytes] of Object.entries(entries)) {
      if (name.endsWith("/") || bytes.length === 0) continue;
      docs.push(...extractJsonDocuments(Buffer.from(bytes), name, depth + 1));
    }
    return docs;
  }
  if (looksLikeJson(buf)) {
    return [{ name: filename || "report.json", json: buf.toString("utf8").replace(/^ /, "") }];
  }
  return [];
}

function toSeconds(value) {
  const ms = Date.parse(String(value || ""));
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
}

function integer(value) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.max(0, Math.floor(n)) : 0;
}

function list(value) {
  if (Array.isArray(value)) return value.map((v) => String(v)).filter(Boolean);
  return value === undefined || value === null || value === "" ? [] : [String(value)];
}

/**
 * Parses one TLS report into a plain shape:
 *   { orgName, reportId, contactInfo, rangeBegin, rangeEnd, policies: [
 *       { policyType, policyDomain, policyString: [..], mxHosts: [..], successful, failed,
 *         failures: [{ resultType, sendingMtaIp, receivingMxHostname, receivingMxHelo, receivingIp,
 *                      failedSessionCount, additionalInformation, failureReasonCode }] } ] }
 * Throws NotATlsReportError for JSON that is something else.
 */
function parseTlsReport(json) {
  let doc;
  try {
    doc = typeof json === "string" ? JSON.parse(json) : json;
  } catch (error) {
    throw new Error(`not valid JSON: ${error.message}`, { cause: error });
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    throw new NotATlsReportError("JSON is not an object");
  }
  const policies = doc.policies;
  if (!Array.isArray(policies) || !("date-range" in doc) || !("organization-name" in doc || "report-id" in doc)) {
    throw new NotATlsReportError("JSON has no policies/date-range: not a TLS report");
  }
  const range = doc["date-range"] || {};
  const rangeBegin = toSeconds(range["start-datetime"]);
  const rangeEnd = toSeconds(range["end-datetime"]);
  if (rangeBegin === null || rangeEnd === null) {
    throw new Error("the report's date-range is missing or unreadable");
  }
  const orgName = String(doc["organization-name"] || "").trim() || "unknown reporter";
  const reportId = String(doc["report-id"] || "").trim() || `${orgName}-${rangeBegin}-${rangeEnd}`;

  const out = [];
  for (const entry of policies) {
    if (!entry || typeof entry !== "object") continue;
    const policy = entry.policy || {};
    const summary = entry.summary || {};
    const policyType = String(policy["policy-type"] || "").toLowerCase();
    const failures = (Array.isArray(entry["failure-details"]) ? entry["failure-details"] : []).map((f) => ({
      resultType: String(f["result-type"] || "unknown").toLowerCase(),
      sendingMtaIp: f["sending-mta-ip"] ? String(f["sending-mta-ip"]).toLowerCase() : null,
      receivingMxHostname: f["receiving-mx-hostname"] ? String(f["receiving-mx-hostname"]).toLowerCase() : null,
      receivingMxHelo: f["receiving-mx-helo"] ? String(f["receiving-mx-helo"]).toLowerCase() : null,
      receivingIp: f["receiving-ip"] ? String(f["receiving-ip"]).toLowerCase() : null,
      failedSessionCount: integer(f["failed-session-count"]),
      additionalInformation: f["additional-information"] ? String(f["additional-information"]) : null,
      failureReasonCode: f["failure-reason-code"] ? String(f["failure-reason-code"]) : null
    }));
    const failed = integer(summary["total-failure-session-count"]) || failures.reduce((n, f) => n + f.failedSessionCount, 0);
    out.push({
      policyType: POLICY_TYPES.has(policyType) ? policyType : policyType || "unknown",
      policyDomain: String(policy["policy-domain"] || "").trim().toLowerCase() || null,
      policyString: list(policy["policy-string"]),
      mxHosts: list(policy["mx-host"]).map((h) => h.toLowerCase()),
      successful: integer(summary["total-successful-session-count"]),
      failed,
      failures
    });
  }
  if (!out.length) {
    throw new Error("the report lists no policies");
  }
  return { orgName, reportId, contactInfo: doc["contact-info"] ? String(doc["contact-info"]) : null, rangeBegin, rangeEnd, policies: out };
}

/** Plain-language meaning of a result type, for the UI and alerts. */
function describeResultType(type) {
  switch (type) {
    case "starttls-not-supported": return "the receiving server did not offer STARTTLS";
    case "certificate-host-mismatch": return "the certificate does not match the MX host name";
    case "certificate-expired": return "the certificate has expired";
    case "certificate-not-trusted": return "the certificate chain is not trusted";
    case "validation-failure": return "the certificate failed validation for another reason";
    case "tlsa-invalid": return "the DANE TLSA record is invalid";
    case "dnssec-invalid": return "DNSSEC validation of the TLSA record failed";
    case "dane-required": return "DANE was required but could not be used";
    case "sts-policy-fetch-error": return "the MTA-STS policy could not be fetched over HTTPS";
    case "sts-policy-invalid": return "the MTA-STS policy file is invalid";
    case "sts-webpki-invalid": return "the MTA-STS policy host's certificate is invalid";
    default: return "an unlisted failure";
  }
}

module.exports = { extractJsonDocuments, parseTlsReport, describeResultType, looksLikeJson, NotATlsReportError, RESULT_TYPES, POLICY_TYPES };
