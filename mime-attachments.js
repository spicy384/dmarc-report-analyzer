/**
 * Pulls what the sync needs out of a raw RFC 822 message: the envelope headers
 * and every attachment as bytes. Used by the sources that hand over whole
 * messages (IMAP, POP3, Gmail, S3); Microsoft Graph lists attachments itself.
 *
 * Binary-safe: the message is handled as latin1 so each character is one byte,
 * and base64 / quoted-printable bodies are decoded straight to Buffers. (The
 * ARF parser's MIME reader decodes to text, which would corrupt zip and gzip.)
 */
const { splitHeaders, parseContentType, decodeHeaderWords } = require("./arf-parser");

const MAX_DEPTH = 8;

function header(headers, name) {
  const lower = name.toLowerCase();
  const hit = headers.find(([n]) => n.toLowerCase() === lower);
  return hit ? hit[1] : null;
}

function decodeQuotedPrintable(text) {
  return text
    .replace(/=\r?\n/g, "")
    .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

function decodeToBuffer(body, encoding) {
  const enc = String(encoding || "").trim().toLowerCase();
  if (enc === "base64") return Buffer.from(body.replace(/[^A-Za-z0-9+/=]/g, ""), "base64");
  if (enc === "quoted-printable") return Buffer.from(decodeQuotedPrintable(body), "latin1");
  return Buffer.from(body, "latin1");
}

/** A parameter value that may be RFC 2231 (name*=UTF-8''x%20y) or RFC 2047 encoded. */
function decodeParam(params, key) {
  const star = params[`${key}*`];
  if (star) {
    const m = String(star).match(/^([^']*)'[^']*'(.*)$/);
    try {
      return m ? decodeURIComponent(m[2]) : decodeURIComponent(star);
    } catch {
      return m ? m[2] : star;
    }
  }
  // Continuations: name*0=, name*1=, ...
  const pieces = Object.keys(params).filter((k) => k.startsWith(`${key}*`) && /\*\d+\*?$/.test(k)).sort((a, b) => parseInt(a.split("*")[1], 10) - parseInt(b.split("*")[1], 10));
  if (pieces.length) return pieces.map((k) => params[k]).join("");
  const plain = params[key];
  return plain ? decodeHeaderWords(plain) : null;
}

function splitMultipart(body, boundary) {
  const marker = `--${boundary}`;
  const chunks = [];
  let current = null;
  for (const line of body.split("\n")) {
    const bare = line.replace(/\r$/, "");
    if (bare === marker || bare === `${marker}--`) {
      if (current) chunks.push(current.join("\n"));
      if (bare.endsWith("--") && bare !== marker) {
        current = null;
        break;
      }
      current = [];
      continue;
    }
    if (current) current.push(line);
  }
  if (current && current.length) chunks.push(current.join("\n"));
  return chunks;
}

function walk(text, depth, out) {
  const { headers, body } = splitHeaders(text);
  const contentType = parseContentType(header(headers, "Content-Type"));
  if (contentType.type.startsWith("multipart/") && contentType.params.boundary && depth < MAX_DEPTH) {
    for (const chunk of splitMultipart(body, contentType.params.boundary)) walk(chunk, depth + 1, out);
    return;
  }
  const disposition = parseContentType(header(headers, "Content-Disposition") || "inline");
  const name = decodeParam(disposition.params, "filename") || decodeParam(contentType.params, "name");
  // Unnamed text parts are the message body, except XML: a few reporters send the report inline.
  const isText = contentType.type.startsWith("text/") && !name && contentType.type !== "text/xml";
  if (contentType.type.startsWith("message/")) {
    // An attached message (or feedback report) is what a forensic report carries; the ARF parser reads it from the raw MIME.
    out.hasMessagePart = true;
    return;
  }
  if (isText) return;
  out.attachments.push({
    name: name || `attachment.${(contentType.type.split("/")[1] || "bin").replace(/[^a-z0-9.+-]/gi, "")}`,
    contentType: contentType.type,
    bytes: decodeToBuffer(body, header(headers, "Content-Transfer-Encoding"))
  });
}

/**
 * @param raw Buffer or string of a whole message
 * @returns { subject, from, date (unix seconds or null), messageId, attachments: [{ name, contentType, bytes }],
 *            hasMessagePart (true when a message/* part was present, the shape of a forensic report) }
 */
function extractMessage(raw) {
  const text = Buffer.isBuffer(raw) ? raw.toString("latin1") : String(raw);
  const { headers } = splitHeaders(text);
  const dateHeader = header(headers, "Date");
  const parsedDate = dateHeader ? Date.parse(dateHeader) : NaN;
  const fromRaw = decodeHeaderWords(header(headers, "From") || "");
  const fromAddr = (fromRaw.match(/<([^>]+)>/) || [null, fromRaw])[1].trim();
  const out = { attachments: [], hasMessagePart: false };
  walk(text, 0, out);
  return {
    subject: decodeHeaderWords(header(headers, "Subject") || "") || null,
    from: fromAddr || null,
    date: Number.isFinite(parsedDate) ? Math.floor(parsedDate / 1000) : null,
    messageId: header(headers, "Message-ID") || null,
    attachments: out.attachments,
    hasMessagePart: out.hasMessagePart
  };
}

module.exports = { extractMessage };
