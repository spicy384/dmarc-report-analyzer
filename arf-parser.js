/**
 * Forensic (ruf) DMARC reports arrive as ARF messages (RFC 5965 / RFC 6591):
 * a multipart/report email holding a human-readable part, a
 * message/feedback-report part with the machine-readable fields, and the
 * original message (or its headers) as message/rfc822 or text/rfc822-headers.
 *
 * This is a small MIME reader (headers, nested multipart, base64 and
 * quoted-printable) plus the ARF field extraction. Pure functions, no I/O.
 */

const HEADER_LIMIT = 8 * 1024;

class NotArfError extends Error {
  constructor(message) {
    super(message);
    this.name = "NotArfError";
    this.code = "not_arf";
  }
}

/** Splits raw message text into { headers: [[name, value]], body }. Header lines may be folded. */
function splitHeaders(text) {
  const normalised = text.replace(/\r\n/g, "\n");
  const end = normalised.indexOf("\n\n");
  const head = end < 0 ? normalised : normalised.slice(0, end);
  const body = end < 0 ? "" : normalised.slice(end + 2);
  const headers = [];
  for (const line of head.split("\n")) {
    if (!line) continue;
    if (/^[ \t]/.test(line) && headers.length) {
      headers[headers.length - 1][1] += " " + line.trim();
      continue;
    }
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    headers.push([line.slice(0, colon).trim(), line.slice(colon + 1).trim()]);
  }
  return { headers, body };
}

function header(headers, name) {
  const lower = name.toLowerCase();
  const hit = headers.find(([n]) => n.toLowerCase() === lower);
  return hit ? hit[1] : null;
}

function headerAll(headers, name) {
  const lower = name.toLowerCase();
  return headers.filter(([n]) => n.toLowerCase() === lower).map(([, v]) => v);
}

/** Parses "type/subtype; param=value; param="quoted"" into { type, params }. */
function parseContentType(value) {
  const [typePart, ...rest] = String(value || "text/plain").split(";");
  const params = {};
  for (const p of rest) {
    const eq = p.indexOf("=");
    if (eq < 0) continue;
    const k = p.slice(0, eq).trim().toLowerCase();
    let v = p.slice(eq + 1).trim();
    if (v.startsWith("\"") && v.endsWith("\"")) v = v.slice(1, -1);
    params[k] = v;
  }
  return { type: typePart.trim().toLowerCase(), params };
}

function decodeQuotedPrintable(text) {
  return text
    .replace(/=\r?\n/g, "")
    .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

/** Decodes a body according to Content-Transfer-Encoding; returns a string (UTF-8 assumed). */
function decodeBody(body, encoding) {
  const enc = String(encoding || "").trim().toLowerCase();
  if (enc === "base64") {
    return Buffer.from(body.replace(/\s+/g, ""), "base64").toString("utf8");
  }
  if (enc === "quoted-printable") {
    return Buffer.from(decodeQuotedPrintable(body), "latin1").toString("utf8");
  }
  return body;
}

/** Decodes RFC 2047 encoded words in a header value (=?utf-8?B?...?= / =?utf-8?Q?...?=). */
function decodeHeaderWords(value) {
  if (!value) return value;
  return String(value).replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_, charset, enc, text) => {
    try {
      if (enc.toUpperCase() === "B") {
        return Buffer.from(text, "base64").toString(/utf-?8/i.test(charset) ? "utf8" : "latin1");
      }
      return Buffer.from(decodeQuotedPrintable(text.replace(/_/g, " ")), "latin1").toString(/utf-?8/i.test(charset) ? "utf8" : "latin1");
    } catch {
      return text;
    }
  });
}

/**
 * Parses a MIME entity into { headers, contentType, body, parts }. `body` is the
 * decoded text for non-multipart entities; `parts` holds the child entities.
 */
function parseMime(raw, depth = 0) {
  const text = Buffer.isBuffer(raw) ? raw.toString("utf8") : String(raw);
  const { headers, body } = splitHeaders(text);
  const contentType = parseContentType(header(headers, "Content-Type"));
  const entity = { headers, contentType, body: "", parts: [] };

  if (contentType.type.startsWith("multipart/") && contentType.params.boundary && depth < 8) {
    const boundary = contentType.params.boundary;
    const marker = `--${boundary}`;
    const lines = body.split("\n");
    const chunks = [];
    let current = null;
    for (const line of lines) {
      if (line === marker || line === `${marker}--` || line.replace(/\r$/, "") === marker || line.replace(/\r$/, "") === `${marker}--`) {
        if (current) chunks.push(current.join("\n"));
        if (line.replace(/\r$/, "").endsWith("--")) {
          current = null;
          break;
        }
        current = [];
        continue;
      }
      if (current) current.push(line);
    }
    if (current && current.length) chunks.push(current.join("\n"));
    entity.parts = chunks.map((chunk) => parseMime(chunk, depth + 1));
    return entity;
  }

  entity.body = decodeBody(body, header(headers, "Content-Transfer-Encoding"));
  return entity;
}

function findPart(entity, predicate) {
  if (predicate(entity)) return entity;
  for (const p of entity.parts) {
    const hit = findPart(p, predicate);
    if (hit) return hit;
  }
  return null;
}

function toSeconds(dateText) {
  if (!dateText) return null;
  const ms = Date.parse(dateText);
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
}

function bareAddress(value) {
  if (!value) return null;
  const m = /<([^>]+)>/.exec(value);
  return (m ? m[1] : value).trim().toLowerCase() || null;
}

/**
 * Parses a raw ARF email. Throws NotArfError when there is no feedback-report part.
 * Returns the fields the analyzer stores.
 */
function parseArf(raw) {
  const root = parseMime(raw);
  const feedback = findPart(root, (e) => e.contentType.type === "message/feedback-report");
  if (!feedback) {
    throw new NotArfError("No message/feedback-report part");
  }

  // The feedback-report body is itself a header block.
  const fields = splitHeaders(feedback.body.trim() + "\n\n").headers;
  const get = (name) => header(fields, name);

  const original = findPart(root, (e) => e.contentType.type === "message/rfc822" || e.contentType.type === "text/rfc822-headers");
  let originalHeaders = [];
  let headersText = null;
  if (original) {
    const parsed = splitHeaders(original.body);
    originalHeaders = parsed.headers;
    const raw2 = original.body.replace(/\r\n/g, "\n");
    const cut = raw2.indexOf("\n\n");
    headersText = (cut < 0 ? raw2 : raw2.slice(0, cut)).slice(0, HEADER_LIMIT);
  }
  const oh = (name) => decodeHeaderWords(header(originalHeaders, name));

  const authFailure = (get("Auth-Failure") || "").toLowerCase() || null;
  const feedbackType = (get("Feedback-Type") || "").toLowerCase() || null;
  const reportedDomain = (get("Reported-Domain") || "").toLowerCase() || null;
  const sourceIp = (get("Source-IP") || "").trim() || null;
  const arrivalAt = toSeconds(get("Arrival-Date") || get("Received-Date")) || toSeconds(oh("Date")) || toSeconds(header(root.headers, "Date"));

  return {
    feedbackType,
    authFailure,
    reportedDomain,
    sourceIp,
    arrivalAt,
    reportingMta: get("Reporting-MTA"),
    originalMailFrom: bareAddress(get("Original-Mail-From")),
    originalRcptTo: bareAddress(get("Original-Rcpt-To")),
    authenticationResults: get("Authentication-Results"),
    dkimDomain: (get("DKIM-Domain") || "").toLowerCase() || null,
    dkimSelector: get("DKIM-Selector") || null,
    deliveryResult: (get("Delivery-Result") || "").toLowerCase() || null,
    originalFrom: oh("From"),
    originalTo: oh("To"),
    originalSubject: oh("Subject"),
    originalDate: toSeconds(oh("Date")),
    originalMessageId: (oh("Message-ID") || "").trim() || null,
    headers: headersText,
    reporterFrom: bareAddress(header(root.headers, "From")),
    subject: decodeHeaderWords(header(root.headers, "Subject"))
  };
}

/** Whether an email looks like it might be an ARF report, cheap enough to decide from the listing. */
function looksLikeArf({ subject, from, attachments = [] } = {}) {
  if (attachments.some((a) => /feedback-report|rfc822/i.test(a.contentType || ""))) return true;
  const s = String(subject || "");
  return /\b(forensic|failure report|feedback report|dmarc)\b/i.test(s) && !/aggregate/i.test(s);
}

module.exports = { parseMime, parseArf, looksLikeArf, NotArfError, decodeHeaderWords, parseContentType, splitHeaders };
