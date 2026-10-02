/**
 * Turns bytes into stored reports, whatever they are: a DMARC aggregate report in
 * any of its containers, a TLS report (RFC 8460) as JSON or gzip, or a whole email
 * (.eml) that is either a forensic ARF report or carries report attachments. The
 * mailbox sync and the manual upload both go through here, so a file dropped on
 * the dashboard is treated exactly like the same file arriving by mail.
 *
 * Content problems are returned, never thrown: a malformed report must not stop
 * the rest of the message or the rest of the upload.
 */
const { extractXmlDocuments, parseAggregateReport } = require("./dmarc-parser");
const { extractJsonDocuments, parseTlsReport } = require("./tlsrpt-parser");
const { parseArf } = require("./arf-parser");
const { extractMessage } = require("./mime-attachments");

function emptyResult() {
  return {
    found: 0,
    aggregate: { added: 0, duplicates: 0, ids: [] },
    tls: { added: 0, duplicates: 0, ids: [] },
    forensic: { added: 0, duplicates: 0 },
    problems: []
  };
}

function merge(into, from) {
  into.found += from.found;
  for (const key of ["aggregate", "tls"]) {
    into[key].added += from[key].added;
    into[key].duplicates += from[key].duplicates;
    into[key].ids.push(...from[key].ids);
  }
  into.forensic.added += from.forensic.added;
  into.forensic.duplicates += from.forensic.duplicates;
  into.problems.push(...from.problems);
  return into;
}

/** True when the bytes read like an RFC 5322 message: header lines first. */
function looksLikeEmail(bytes, name = "") {
  if (/\.eml$/i.test(name)) return true;
  const head = Buffer.from(bytes).subarray(0, 4096).toString("latin1");
  return /^(?:[A-Za-z][A-Za-z0-9-]*:\s|From )/.test(head) && /\r?\n(?:Received|From|To|Subject|Message-ID|Content-Type|Date|Return-Path|MIME-Version):/i.test(`\n${head}`);
}

function createIngest({ db }) {
  /** One attachment or file: aggregate reports (XML in any container) and TLS reports (JSON, maybe gzipped). */
  function ingestBytes({ bytes, name = "", messageId, mailboxId }) {
    const out = emptyResult();
    const label = name || "attachment";
    let xmlDocs = [];
    try {
      xmlDocs = extractXmlDocuments(bytes, name);
    } catch (error) {
      out.problems.push(`${label}: ${error.message}`);
      return out;
    }
    for (const doc of xmlDocs) {
      let parsed;
      try {
        parsed = parseAggregateReport(doc.xml);
      } catch (error) {
        if (error.code === "not_a_report") continue; // some other XML riding along (signatures, calendar items)
        out.problems.push(`${doc.name}: ${error.message}`);
        continue;
      }
      const result = db.insertReport({ messageId, mailboxId, attachmentName: doc.name || name, parsed, xml: doc.xml });
      out.found += 1;
      if (result.duplicate) {
        out.aggregate.duplicates += 1;
      } else {
        out.aggregate.added += 1;
        out.aggregate.ids.push(result.reportId);
      }
    }

    let jsonDocs = [];
    try {
      jsonDocs = extractJsonDocuments(bytes, name);
    } catch (error) {
      if (!xmlDocs.length) out.problems.push(`${label}: ${error.message}`);
    }
    for (const doc of jsonDocs) {
      let parsed;
      try {
        parsed = parseTlsReport(doc.json);
      } catch (error) {
        if (error.code === "not_a_report") continue;
        out.problems.push(`${doc.name}: ${error.message}`);
        continue;
      }
      const result = db.insertTlsReport({ messageId, mailboxId, attachmentName: doc.name || name, parsed, json: doc.json });
      out.found += 1;
      out.tls.added += result.added;
      out.tls.duplicates += result.duplicates;
      out.tls.ids.push(...result.ids);
    }
    return out;
  }

  /** A whole email: a forensic ARF report, or a carrier of report attachments. */
  function ingestEmail({ raw, name = "", messageId, mailboxId }) {
    const out = emptyResult();
    try {
      const parsed = parseArf(raw);
      const result = db.insertForensic({ messageId, mailboxId, parsed });
      out.found += 1;
      if (result.duplicate) out.forensic.duplicates += 1;
      else out.forensic.added += 1;
      return { ...out, subject: parsed.originalSubject || null, from: parsed.reporterFrom || null };
    } catch (error) {
      if (error.code !== "not_arf") {
        out.problems.push(`${name || "message"}: ${error.message}`);
        return out;
      }
    }
    let message;
    try {
      message = extractMessage(raw);
    } catch (error) {
      out.problems.push(`${name || "message"}: ${error.message}`);
      return out;
    }
    for (const att of message.attachments || []) {
      merge(out, ingestBytes({ bytes: att.bytes, name: att.name, messageId, mailboxId }));
    }
    if (!message.attachments || !message.attachments.length) {
      out.problems.push(`${name || "message"}: the email has no attachments and is not a forensic report`);
    }
    return { ...out, subject: message.subject, from: message.from };
  }

  /** A manually uploaded file: decides by content whether it is an email or a report container. */
  function ingestFile({ bytes, name = "", messageId, mailboxId }) {
    if (looksLikeEmail(bytes, name)) {
      return ingestEmail({ raw: bytes, name, messageId, mailboxId });
    }
    const out = ingestBytes({ bytes, name, messageId, mailboxId });
    if (!out.found && !out.problems.length) {
      out.problems.push(`${name || "file"}: not a DMARC aggregate report, a TLS report or an email (checked for XML, JSON, zip and gzip)`);
    }
    return out;
  }

  return { ingestBytes, ingestEmail, ingestFile, looksLikeEmail };
}

module.exports = { createIngest, looksLikeEmail };
