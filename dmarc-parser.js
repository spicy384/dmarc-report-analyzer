/**
 * DMARC aggregate report parsing (RFC 7489 section 7.2). Pure functions, no I/O,
 * so they are exercised directly by the tests.
 *
 * A report arrives as an email attachment that is one of:
 *   - a .zip holding one (rarely several) .xml files      (Google, Yahoo, most others)
 *   - a .xml.gz                                            (Microsoft, Mimecast)
 *   - a bare .xml                                          (small senders, some appliances)
 * Senders regularly mislabel the content type, so the container is detected from
 * the first bytes rather than from the filename or MIME type.
 */
const zlib = require("zlib");
const { unzipSync } = require("fflate");
const { XMLParser } = require("fast-xml-parser");

/** Thrown when an attachment is XML but not a DMARC aggregate report. */
class NotAReportError extends Error {
  constructor(message) {
    super(message);
    this.name = "NotAReportError";
    this.code = "not_a_report";
  }
}

const MAX_CONTAINER_DEPTH = 3;
const MAX_XML_BYTES = 50 * 1024 * 1024;

function isGzip(buf) {
  return buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b;
}

function isZip(buf) {
  return buf.length > 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04;
}

/** True when the bytes look like an XML document: optional BOM and whitespace, then a "<". */
function looksLikeXml(buf) {
  let i = 0;
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    i = 3;
  }
  while (i < buf.length && (buf[i] === 0x20 || buf[i] === 0x09 || buf[i] === 0x0a || buf[i] === 0x0d)) {
    i += 1;
  }
  return i < buf.length && buf[i] === 0x3c;
}

/**
 * Unpacks an attachment into the XML documents it holds.
 * Returns [{ name, xml }] - empty when the bytes are not XML and not a container of XML.
 */
function extractXmlDocuments(buffer, filename = "", depth = 0) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  if (depth > MAX_CONTAINER_DEPTH) {
    throw new Error(`${filename || "attachment"}: containers nested too deeply`);
  }

  if (isGzip(buf)) {
    const inner = zlib.gunzipSync(buf, { maxOutputLength: MAX_XML_BYTES });
    const innerName = filename.replace(/\.gz$/i, "") || "report.xml";
    return extractXmlDocuments(inner, innerName, depth + 1);
  }

  if (isZip(buf)) {
    const entries = unzipSync(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
    const docs = [];
    for (const [name, bytes] of Object.entries(entries)) {
      if (name.endsWith("/") || bytes.length === 0) {
        continue; // directory entry
      }
      docs.push(...extractXmlDocuments(Buffer.from(bytes), name, depth + 1));
    }
    return docs;
  }

  if (looksLikeXml(buf)) {
    return [{ name: filename || "report.xml", xml: buf.toString("utf8").replace(/^﻿/, "") }];
  }

  return [];
}

// Elements that may repeat and must always come back as arrays, even with one child.
const ARRAY_PATHS = new Set([
  "feedback.record",
  "feedback.record.row.policy_evaluated.reason",
  "feedback.record.auth_results.dkim",
  "feedback.record.auth_results.spf",
  "feedback.report_metadata.error"
]);

const parser = new XMLParser({
  ignoreAttributes: true,
  removeNSPrefix: true,
  parseTagValue: false,
  trimValues: true,
  isArray: (name, jpath) => ARRAY_PATHS.has(jpath)
});

function text(value) {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value === "object") {
    // A tag with only whitespace/children parses to an object; treat as empty.
    return typeof value["#text"] === "string" ? value["#text"].trim() || null : null;
  }
  const s = String(value).trim();
  return s === "" ? null : s;
}

function lower(value) {
  const s = text(value);
  return s === null ? null : s.toLowerCase();
}

function integer(value, fallback = null) {
  const s = text(value);
  if (s === null) {
    return fallback;
  }
  const n = Number(s);
  return Number.isFinite(n) ? Math.trunc(n) : fallback;
}

function asArray(value) {
  if (value === undefined || value === null) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

/**
 * Parses one aggregate report XML document into a plain object:
 *   { metadata, policy, records }
 * Throws NotAReportError if the XML is something else entirely, and a plain Error
 * if it is a feedback document that is missing the parts every report must have.
 */
function parseAggregateReport(xml) {
  let doc;
  try {
    doc = parser.parse(xml);
  } catch (error) {
    throw new Error(`XML could not be parsed: ${error.message}`);
  }

  const feedback = doc && doc.feedback;
  if (!feedback || typeof feedback !== "object") {
    const root = doc && typeof doc === "object" ? Object.keys(doc).filter((k) => k !== "?xml")[0] : null;
    throw new NotAReportError(root ? `Root element is <${root}>, not <feedback>` : "No root element");
  }

  const meta = feedback.report_metadata || {};
  const range = meta.date_range || {};
  const pub = feedback.policy_published || {};

  const metadata = {
    orgName: text(meta.org_name),
    email: text(meta.email),
    extraContactInfo: text(meta.extra_contact_info),
    reportId: text(meta.report_id),
    dateRange: { begin: integer(range.begin), end: integer(range.end) },
    errors: asArray(meta.error).map(text).filter(Boolean)
  };

  const policy = {
    domain: lower(pub.domain),
    adkim: lower(pub.adkim),
    aspf: lower(pub.aspf),
    p: lower(pub.p),
    sp: lower(pub.sp),
    pct: integer(pub.pct, 100),
    fo: text(pub.fo)
  };

  if (!metadata.orgName && !metadata.reportId) {
    throw new Error("feedback document has no report_metadata");
  }
  if (!policy.domain) {
    throw new Error("feedback document has no policy_published/domain");
  }
  if (metadata.dateRange.begin === null || metadata.dateRange.end === null) {
    throw new Error("feedback document has no date_range");
  }

  const records = asArray(feedback.record).map((rec, index) => {
    const row = rec.row || {};
    const evaluated = row.policy_evaluated || {};
    const ids = rec.identifiers || {};
    const auth = rec.auth_results || {};

    const sourceIp = text(row.source_ip);
    if (!sourceIp) {
      throw new Error(`record ${index + 1} has no source_ip`);
    }

    const dkimEval = lower(evaluated.dkim);
    const spfEval = lower(evaluated.spf);
    const dkimResults = asArray(auth.dkim).map((d) => ({
      domain: lower(d.domain),
      selector: text(d.selector),
      result: lower(d.result),
      humanResult: text(d.human_result)
    }));
    const spfResults = asArray(auth.spf).map((s) => ({
      domain: lower(s.domain),
      scope: lower(s.scope),
      result: lower(s.result)
    }));

    return {
      sourceIp,
      count: Math.max(1, integer(row.count, 1)),
      disposition: lower(evaluated.disposition) || "none",
      dkimEval,
      spfEval,
      // DMARC passes when either aligned mechanism passes.
      passed: dkimEval === "pass" || spfEval === "pass",
      reasons: asArray(evaluated.reason).map((r) => ({ type: lower(r.type), comment: text(r.comment) })),
      envelopeTo: lower(ids.envelope_to),
      envelopeFrom: lower(ids.envelope_from),
      headerFrom: lower(ids.header_from),
      dkimResults,
      spfResults,
      dkimDomain: dkimResults.length ? dkimResults[0].domain : null,
      spfDomain: spfResults.length ? spfResults[0].domain : null
    };
  });

  return { metadata, policy, records };
}

/** Totals for one parsed report: messages, passes, failures. */
function summarizeRecords(records) {
  let messages = 0;
  let passed = 0;
  for (const r of records) {
    messages += r.count;
    if (r.passed) {
      passed += r.count;
    }
  }
  return { messages, passed, failed: messages - passed };
}

module.exports = {
  NotAReportError,
  extractXmlDocuments,
  parseAggregateReport,
  summarizeRecords,
  looksLikeXml,
  isGzip,
  isZip
};
