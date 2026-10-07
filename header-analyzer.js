/**
 * Analyses the headers of one email: who it claims to be from, what the receiving
 * server concluded about SPF, DKIM, DMARC and ARC, whether those results align
 * with the From domain, the path it took hop by hop with the time spent on each,
 * the DKIM signatures it carries (checked against DNS), the address that handed
 * it to the receiver, and what the spam filter stamped on it (Microsoft 365 in
 * detail, SpamAssassin-style scores generically). Parsing is pure; the DNS and
 * enrichment lookups are injected so tests run offline. Nothing is stored.
 */
const { splitHeaders, decodeHeaderWords } = require("./arf-parser");
const { parseIp } = require("./ipmatch");
const { matchCatalogue } = require("./sender-catalogue");
const { organizationalDomain: orgDomain } = require("./domains");

const MAX_INPUT_BYTES = 512 * 1024;
const MAX_DKIM_LOOKUPS = 6;
const MAX_ADDRESS_HEADER = 2048; // an address header longer than this is not an address

function fail(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

// --- header block ---------------------------------------------------------------

/** Turns pasted text into [{ name, value }], unfolding continuation lines and dropping any body. */
function parseHeaderBlock(raw) {
  let text = String(raw || "").replace(/^\uFEFF/, "").replace(/\r\n/g, "\n");
  // Leading blank lines and an mbox "From " line are not headers.
  text = text.replace(/^\s*\n/, "").replace(/^From [^\n]*\n/, "");
  const { headers } = splitHeaders(text);
  return headers.map(([name, value]) => ({ name, value }));
}

function valuesOf(headers, name) {
  const lower = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === lower).map((h) => h.value);
}

function first(headers, name) {
  const all = valuesOf(headers, name);
  return all.length ? all[0] : null;
}

/** Display name, address and domain out of a From-like header value. */
function parseAddress(value) {
  if (!value) return null;
  const decoded = decodeHeaderWords(String(value).slice(0, MAX_ADDRESS_HEADER)).trim();
  const angle = decoded.match(/<([^<>]*)>\s*$/) || decoded.match(/<([^<>]*)>/);
  const address = (angle ? angle[1] : (decoded.match(/[^\s<>"(),;:]+@[^\s<>"(),;:]+/) || [""])[0]).trim().toLowerCase();
  const name = angle ? decoded.slice(0, angle.index).trim().replace(/^"(.*)"$/, "$1").trim() : "";
  const at = address.lastIndexOf("@");
  return { raw: decoded, name: name || null, address: address || null, domain: at >= 0 ? address.slice(at + 1) : null };
}

function toSeconds(text) {
  const ms = Date.parse(String(text || "").replace(/\s*\([^)]*\)\s*$/, ""));
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
}

// --- addresses --------------------------------------------------------------------

function isPrivateIp(ip) {
  const s = String(ip || "").toLowerCase();
  if (!s) return true;
  if (s.includes(":")) {
    return s === "::1" || s.startsWith("fe80:") || s.startsWith("fc") || s.startsWith("fd") || s === "::";
  }
  const p = s.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n))) return true;
  return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 192 && p[1] === 168) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31)
    || (p[0] === 169 && p[1] === 254) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
}

/** Every IP literal in a piece of text, in order. */
function findIps(text) {
  const out = [];
  const re = /\[?(?:IPv6:)?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}(?:\.\d{1,3}){0,3})\]?/g;
  let m;
  while ((m = re.exec(String(text || ""))) !== null) {
    const candidate = m[1].toLowerCase();
    if (parseIp(candidate)) out.push(candidate);
  }
  return out;
}

// --- Received ---------------------------------------------------------------------

/** One Received header: who handed the message to whom, how and when. */
function parseReceived(value) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  const semi = text.lastIndexOf(";");
  const date = semi >= 0 ? toSeconds(text.slice(semi + 1)) : null;
  const main = semi >= 0 ? text.slice(0, semi) : text;
  const byIndex = main.search(/\bby\s/i);
  const fromPart = byIndex >= 0 ? main.slice(0, byIndex) : main;
  const rest = byIndex >= 0 ? main.slice(byIndex) : "";
  const fromMatch = fromPart.match(/\bfrom\s+(\S+)/i);
  const ips = findIps(fromPart.replace(/\bfrom\s+\S+/i, " "));
  const fromHostIp = fromMatch && parseIp(fromMatch[1].replace(/^\[|\]$/g, "").toLowerCase()) ? fromMatch[1].replace(/^\[|\]$/g, "").toLowerCase() : null;
  const pick = (re) => ((rest.match(re) || [])[1] || null);
  const withProto = pick(/\bwith\s+([^\s;()]+)/i);
  return {
    from: fromMatch ? fromMatch[1].replace(/^\[|\]$/g, "").toLowerCase() : null,
    fromIp: ips.find((ip) => !isPrivateIp(ip)) || ips[0] || fromHostIp || null,
    by: (pick(/\bby\s+([^\s;()]+)/i) || "").toLowerCase() || null,
    with: withProto,
    id: pick(/\bid\s+([^\s;()]+)/i),
    for: (pick(/\bfor\s+<?([^>\s;]+)>?/i) || "").toLowerCase() || null,
    tls: /TLS|\bESMTPS\b|\bESMTPSA\b|\bSMTPS\b|\bUTF8SMTPS/i.test(main) ? ((main.match(/TLSv?[\d._]+|TLS1_\d/i) || ["TLS"])[0]) : null,
    date,
    raw: text
  };
}

/** Hops oldest first, each with the seconds since the previous one. */
function buildHops(headers) {
  const hops = valuesOf(headers, "Received").map(parseReceived).reverse();
  let previous = null;
  hops.forEach((hop, i) => {
    hop.index = i + 1;
    hop.private = hop.fromIp ? isPrivateIp(hop.fromIp) : null;
    hop.delaySeconds = hop.date !== null && previous !== null ? hop.date - previous : null;
    if (hop.date !== null) previous = hop.date;
  });
  return hops;
}

// --- Authentication-Results -----------------------------------------------------------

/** "method=result (comment) prop=value ..." entries of an Authentication-Results value. */
function parseAuthResults(value) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  // Split on semicolons that are not inside parentheses.
  const parts = [];
  let depth = 0;
  let current = "";
  for (const ch of text) {
    if (ch === "(") depth += 1;
    if (ch === ")") depth = Math.max(0, depth - 1);
    if (ch === ";" && depth === 0) {
      parts.push(current.trim());
      current = "";
    } else {
      current += ch;
    }
  }
  if (current.trim()) parts.push(current.trim());

  let authservId = null;
  let instance = null;
  const results = [];
  for (const part of parts) {
    const m = part.match(/^([a-z][a-z0-9-]*)\s*=\s*([a-z0-9_-]+)/i);
    if (!m) {
      const i = part.match(/^i\s*=\s*(\d+)/i);
      if (i) instance = Number(i[1]);
      else if (authservId === null && part && !/=/.test(part.split(" ")[0])) authservId = part.split(" ")[0].toLowerCase();
      continue;
    }
    if (m[1].toLowerCase() === "i" && /^\d+$/.test(m[2])) {
      instance = Number(m[2]);
      continue;
    }
    const comments = [...part.matchAll(/\(([^()]*)\)/g)].map((c) => c[1].trim()).filter(Boolean);
    const bare = part.replace(/\([^()]*\)/g, " ");
    const props = {};
    for (const p of bare.slice(m[0].length).matchAll(/([a-z][a-z0-9.-]*)\s*=\s*("[^"]*"|\S+)/gi)) {
      props[p[1].toLowerCase()] = p[2].replace(/^"|"$/g, "");
    }
    results.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), comment: comments.join("; ") || null, props });
  }
  return { authservId, instance, results, raw: text };
}

function parseReceivedSpf(value) {
  if (!value) return null;
  const text = String(value).replace(/\s+/g, " ").trim();
  const prop = (name) => ((text.match(new RegExp(`\\b${name}=("[^"]*"|[^;\\s]+)`, "i")) || [])[1] || "").replace(/^"|"$/g, "") || null;
  return {
    result: (text.match(/^([a-z]+)/i) || ["", ""])[1].toLowerCase() || null,
    clientIp: (prop("client-ip") || "").toLowerCase() || null,
    envelopeFrom: (prop("envelope-from") || "").replace(/^<|>$/g, "").toLowerCase() || null,
    helo: (prop("helo") || "").toLowerCase() || null,
    receiver: prop("receiver"),
    raw: text
  };
}

// --- DKIM / ARC -----------------------------------------------------------------------

function parseTagList(value) {
  const tags = {};
  for (const part of String(value || "").split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).replace(/\s+/g, " ").trim();
  }
  return tags;
}

function parseDkimSignature(value, { now }) {
  const t = parseTagList(value);
  const signed = (t.h || "").split(":").map((h) => h.trim().toLowerCase()).filter(Boolean);
  const expires = t.x && /^\d+$/.test(t.x) ? Number(t.x) : null;
  return {
    domain: (t.d || "").toLowerCase() || null,
    selector: t.s || null,
    algorithm: t.a || null,
    canonicalization: t.c || "simple/simple",
    identity: t.i || null,
    signedAt: t.t && /^\d+$/.test(t.t) ? Number(t.t) : null,
    expiresAt: expires,
    expired: expires !== null && expires < now,
    bodyLength: t.l !== undefined ? t.l : null,
    signedHeaders: signed,
    signsFrom: signed.includes("from")
  };
}

// --- Microsoft 365 stamps -----------------------------------------------------------

const SFV = {
  NSPM: "not spam", SPM: "marked as spam by the content filter", SKN: "marked not spam before filtering (mail flow rule)", SKB: "marked spam because the sender is blocked in the anti-spam policy",
  SKS: "marked spam before filtering (mail flow rule)", SKA: "skipped filtering: the sender is in the allowed list of the anti-spam policy", SKI: "skipped filtering: intra-organisation or trusted", SKQ: "released from quarantine",
  SFE: "skipped filtering: the recipient's Safe Senders list", BLK: "blocked: the recipient's Blocked Senders list", SKE: "skipped filtering by an Exchange rule"
};
const CAT = {
  NONE: "clean", SPM: "spam", HSPM: "high-confidence spam", BULK: "bulk mail", PHSH: "phishing", HPHSH: "high-confidence phishing", HPHISH: "high-confidence phishing", MALW: "malware",
  SPOOF: "spoofing", DIMP: "domain impersonation", UIMP: "user impersonation", GIMP: "impersonation by mailbox intelligence", BIMP: "brand impersonation", OSPM: "outbound spam", INTOS: "intra-organisation phishing",
  AMP: "anti-malware", SAP: "Safe Attachments", FTBP: "common attachment filter", DMS: "data loss prevention", ETR: "mail flow rule"
};

function sclMeaning(scl) {
  if (scl === null) return null;
  if (scl === -1) return "skipped spam filtering (trusted or allowed)";
  if (scl <= 1) return "not spam";
  if (scl <= 4) return "low spam score, delivered";
  if (scl <= 6) return "spam";
  return "high-confidence spam";
}

function bclMeaning(bcl) {
  if (bcl === null) return null;
  if (bcl === 0) return "not from a bulk sender";
  if (bcl <= 3) return "bulk sender with few complaints";
  if (bcl <= 7) return "bulk sender with a mixed number of complaints";
  return "bulk sender with many complaints";
}

/** What Microsoft's composite authentication reason code says, by its first digit. */
function compauthMeaning(result, reason) {
  const code = String(reason || "");
  const byClass = {
    0: code === "000" ? "explicit failure: the From domain's DMARC policy is reject or quarantine and the message failed" : code === "001" ? "implicit failure: no DMARC record to go by, and SPF and DKIM did not vouch for the From domain" : code === "002" ? "the organisation has a policy that forbids this sender/domain pair from spoofing" : code === "010" ? "DMARC failed, the domain's policy is reject or quarantine, and the sending domain is one of the organisation's own accepted domains" : "failed",
    1: "passed explicit authentication (SPF or DKIM aligned with the From domain)",
    2: "soft pass: implicit authentication",
    3: "not checked",
    4: "bypassed: an allow entry or rule skipped the check",
    6: "failed implicit authentication, and the sending domain is one of the organisation's accepted domains (self-to-self or intra-organisation spoofing)",
    7: "passed implicitly",
    9: "bypassed"
  };
  return byClass[code[0]] || (result ? `composite authentication ${result}` : null);
}

function parseMicrosoft(headers, topAuth) {
  const report = first(headers, "X-Forefront-Antispam-Report") || first(headers, "X-Forefront-Antispam-Report-Untrusted");
  const antispam = first(headers, "X-Microsoft-Antispam") || first(headers, "X-Microsoft-Antispam-Untrusted");
  const sclHeader = first(headers, "X-MS-Exchange-Organization-SCL");
  const authAs = first(headers, "X-MS-Exchange-Organization-AuthAs");
  if (!report && !antispam && sclHeader === null && !authAs) return null;
  const fields = {};
  for (const part of String(report || "").split(";")) {
    const colon = part.indexOf(":");
    if (colon > 0) fields[part.slice(0, colon).trim().toUpperCase()] = part.slice(colon + 1).trim();
  }
  const num = (v) => (v !== undefined && v !== null && /^-?\d+$/.test(String(v).trim()) ? Number(v) : null);
  const scl = num(fields.SCL) ?? num(sclHeader);
  const bcl = num((String(antispam || "").match(/BCL:(-?\d+)/i) || [])[1]);
  const compauth = topAuth ? topAuth.results.find((r) => r.method === "compauth") : null;
  return {
    scl,
    sclMeaning: sclMeaning(scl),
    bcl,
    bclMeaning: bclMeaning(bcl),
    sfv: fields.SFV || null,
    sfvMeaning: fields.SFV ? SFV[fields.SFV] || null : null,
    cat: fields.CAT || null,
    catMeaning: fields.CAT ? CAT[fields.CAT] || null : null,
    cip: fields.CIP ? fields.CIP.toLowerCase() : null,
    country: fields.CTRY || null,
    language: fields.LANG || null,
    // "InfoDomainNonexistent" / "InfoNoRecords" are Microsoft's placeholders for no PTR.
    ptr: fields.PTR && !/^Info/i.test(fields.PTR) ? fields.PTR.toLowerCase() : null,
    helo: fields.H ? fields.H.toLowerCase() : null,
    direction: fields.DIR || null,
    ipVerdict: fields.IPV || null,
    safety: fields.SFTY || null,
    authAs: authAs || null,
    authSource: first(headers, "X-MS-Exchange-Organization-AuthSource"),
    compauth: compauth ? { result: compauth.result, reason: compauth.props.reason || null, meaning: compauthMeaning(compauth.result, compauth.props.reason) } : null
  };
}

function parseOtherFilters(headers) {
  const out = [];
  const add = (name, meaning) => {
    for (const v of valuesOf(headers, name)) out.push({ name, value: v.length > 400 ? `${v.slice(0, 400)}...` : v, meaning });
  };
  add("X-Spam-Status", "SpamAssassin-style verdict: Yes/No, the score and the threshold");
  add("X-Spam-Score", "spam score from the receiving filter");
  add("X-Spam-Flag", "YES when the filter classified the message as spam");
  add("X-Spam-Level", "spam score as a row of asterisks");
  add("X-Spam-Report", "the rules that matched");
  add("X-Barracuda-Spam-Score", "Barracuda spam score");
  add("X-Proofpoint-Spam-Details", "Proofpoint verdict details");
  add("X-Mimecast-Spam-Score", "Mimecast spam score");
  add("X-Mailer", "the program that composed the message");
  add("User-Agent", "the program that composed the message");
  add("X-Originating-IP", "the client address the sending service recorded");
  add("Precedence", "bulk or list marks automated mail");
  add("Auto-Submitted", "set on auto-replies and generated mail");
  add("List-Unsubscribe", "present on legitimate bulk mail");
  add("List-Id", "the mailing list that redistributed the message");
  return out;
}

// --- analysis -------------------------------------------------------------------------

function domainOf(value) {
  const s = String(value || "").toLowerCase().replace(/^<|>$/g, "");
  const at = s.lastIndexOf("@");
  return (at >= 0 ? s.slice(at + 1) : s) || null;
}

function aligned(domain, fromDomain, strict = false) {
  if (!domain || !fromDomain) return false;
  return strict ? domain === fromDomain : orgDomain(domain) === orgDomain(fromDomain);
}

function formatDuration(seconds) {
  const s = Math.abs(Math.round(seconds));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${s % 60} s`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
  return `${Math.floor(s / 86400)} d ${Math.floor((s % 86400) / 3600)} h`;
}

/**
 * `dnsRecords` (dns-records.js), `geoip` and `db` are optional; without them the
 * analysis is purely what the headers say.
 */
function createHeaderAnalyzer({ dnsRecords = null, geoip = null, db = null, now = () => Math.floor(Date.now() / 1000) } = {}) {
  async function analyze(raw) {
    const text = String(raw || "");
    if (!text.trim()) throw fail(400, "Paste the message headers first.");
    if (Buffer.byteLength(text, "utf8") > MAX_INPUT_BYTES) throw fail(413, "That is more than 512 KB; paste only the headers.");
    const headers = parseHeaderBlock(text);
    if (headers.length < 2 || !headers.some((h) => /^(received|from|authentication-results|message-id|date|subject)$/i.test(h.name))) {
      throw fail(400, "That does not look like email headers. Paste the full headers (in Outlook: File > Properties > Internet headers; in Gmail: Show original).");
    }
    const at = now();

    // --- identity ---
    const from = parseAddress(first(headers, "From"));
    const returnPath = parseAddress(first(headers, "Return-Path"));
    const replyTo = parseAddress(first(headers, "Reply-To"));
    const sender = parseAddress(first(headers, "Sender"));
    const fromDomain = from ? from.domain : null;
    const summary = {
      from,
      returnPath,
      replyTo,
      sender,
      to: decodeHeaderWords(first(headers, "To") || "") || null,
      subject: decodeHeaderWords(first(headers, "Subject") || "") || null,
      date: toSeconds(first(headers, "Date")),
      dateRaw: first(headers, "Date"),
      messageId: (first(headers, "Message-ID") || "").trim() || null
    };

    // --- what the receiver concluded ---
    const authHeaders = valuesOf(headers, "Authentication-Results").map(parseAuthResults);
    authHeaders.forEach((a, i) => { a.trusted = i === 0; });
    const top = authHeaders[0] || null;
    const receivedSpf = parseReceivedSpf(first(headers, "Received-SPF"));
    const hops = buildHops(headers);
    const microsoft = parseMicrosoft(headers, top);

    const find = (method) => (top ? top.results.filter((r) => r.method === method) : []);
    const spfAuth = find("spf")[0] || null;
    const spfResult = spfAuth ? spfAuth.result : receivedSpf ? receivedSpf.result : null;
    const spfDomain = domainOf((spfAuth && (spfAuth.props["smtp.mailfrom"] || spfAuth.props["smtp.helo"])) || (receivedSpf && (receivedSpf.envelopeFrom || receivedSpf.helo)) || (returnPath && returnPath.address) || "");
    const dkimAuth = find("dkim");
    const dmarcAuth = find("dmarc")[0] || null;
    const arcAuth = find("arc")[0] || null;

    // --- DNS: the From domain's policy, and each signature's key ---
    let dmarcRecord = null;
    if (dnsRecords && fromDomain) {
      dmarcRecord = await dnsRecords.getDmarc(fromDomain).catch((error) => ({ domain: fromDomain, found: false, error: error.code || error.message, tags: {}, warnings: [] }));
    }
    const strictSpf = Boolean(dmarcRecord && dmarcRecord.tags && dmarcRecord.tags.aspf === "s");
    const strictDkim = Boolean(dmarcRecord && dmarcRecord.tags && dmarcRecord.tags.adkim === "s");

    const signatures = valuesOf(headers, "DKIM-Signature").map((v) => parseDkimSignature(v, { now: at }));
    for (const [i, sig] of signatures.entries()) {
      const match = dkimAuth.find((r) => (r.props["header.d"] || "").toLowerCase() === sig.domain && (!r.props["header.s"] || r.props["header.s"] === sig.selector))
        || dkimAuth.find((r) => (r.props["header.d"] || domainOf(r.props["header.i"] || "")) === sig.domain);
      sig.result = match ? match.result : null;
      sig.resultComment = match ? match.comment : null;
      sig.aligned = aligned(sig.domain, fromDomain, strictDkim);
      sig.dns = null;
      if (dnsRecords && sig.domain && sig.selector && i < MAX_DKIM_LOOKUPS) {
        sig.dns = await dnsRecords.checkDkim(sig.domain, sig.selector).catch((error) => ({ found: false, error: error.code || error.message }));
      }
    }

    // --- verdicts and alignment ---
    const spfAligned = spfResult === "pass" && aligned(spfDomain, fromDomain, strictSpf);
    const dkimPassing = dkimAuth.filter((r) => r.result === "pass").map((r) => (r.props["header.d"] || domainOf(r.props["header.i"] || "") || "").toLowerCase()).filter(Boolean);
    const dkimAlignedDomains = dkimPassing.filter((d) => aligned(d, fromDomain, strictDkim));
    const computedDmarc = !fromDomain || (!spfResult && !dkimAuth.length) ? null : (spfAligned || dkimAlignedDomains.length ? "pass" : "fail");
    const verdicts = {
      spf: { result: spfResult, domain: spfDomain, aligned: spfResult === "pass" ? spfAligned : false, strict: strictSpf, comment: spfAuth ? spfAuth.comment : null },
      dkim: {
        result: dkimAuth.length ? (dkimPassing.length ? "pass" : dkimAuth[0].result) : (signatures.length ? "not reported" : "none"),
        passingDomains: [...new Set(dkimPassing)],
        alignedDomains: [...new Set(dkimAlignedDomains)],
        aligned: dkimAlignedDomains.length > 0,
        strict: strictDkim,
        signatures: signatures.length
      },
      dmarc: {
        reported: dmarcAuth ? dmarcAuth.result : null,
        computed: computedDmarc,
        via: computedDmarc === "pass" ? [spfAligned ? "SPF" : null, dkimAlignedDomains.length ? "DKIM" : null].filter(Boolean) : [],
        action: dmarcAuth ? dmarcAuth.props.action || null : null,
        headerFrom: dmarcAuth ? dmarcAuth.props["header.from"] || null : null,
        policy: dmarcRecord && dmarcRecord.found ? dmarcRecord.tags.p || null : null,
        comment: dmarcAuth ? dmarcAuth.comment : null
      },
      arc: (() => {
        const seals = valuesOf(headers, "ARC-Seal").map(parseTagList).map((t) => ({ instance: Number(t.i) || null, cv: (t.cv || "").toLowerCase() || null, domain: (t.d || "").toLowerCase() || null })).sort((a, b) => (a.instance || 0) - (b.instance || 0));
        if (!seals.length && !arcAuth) return null;
        return { result: arcAuth ? arcAuth.result : null, sets: seals.length, seals, chain: seals.length ? seals[seals.length - 1].cv : null };
      })()
    };

    // --- the address that handed the message to the receiver ---
    const source = { ip: null, how: null };
    const candidates = [
      [spfAuth && (spfAuth.props["smtp.client-ip"] || ((spfAuth.comment || "").match(/sender ip is ([0-9a-f:.]+)/i) || [])[1] || ((spfAuth.comment || "").match(/designates ([0-9a-f:.]+) as/i) || [])[1]), "the receiver's SPF check"],
      [receivedSpf && receivedSpf.clientIp, "the Received-SPF header"],
      [microsoft && microsoft.cip, "Microsoft's connecting-IP stamp (CIP)"]
    ];
    for (const [ip, how] of candidates) {
      const clean = String(ip || "").toLowerCase().replace(/^\[|\]$/g, "");
      if (clean && parseIp(clean)) {
        source.ip = clean;
        source.how = how;
        break;
      }
    }
    if (!source.ip) {
      // Newest hop first: the first public address handed over by a host outside the receiver's own domain.
      for (const hop of [...hops].reverse()) {
        if (hop.fromIp && !isPrivateIp(hop.fromIp) && (!hop.from || !hop.by || orgDomain(hop.from) !== orgDomain(hop.by))) {
          source.ip = hop.fromIp;
          source.how = `hop ${hop.index} of the Received chain (a guess: no SPF client address in the headers)`;
          break;
        }
      }
    }
    if (source.ip) {
      source.private = isPrivateIp(source.ip);
      let ptrName = microsoft && microsoft.cip === source.ip ? microsoft.ptr : null;
      if (dnsRecords && !source.private) {
        const ptr = await dnsRecords.getPtr(source.ip).catch(() => null);
        if (ptr && ptr.found && ptr.names.length) {
          ptrName = ptr.names[0].name;
          source.ptrConfirmed = Boolean(ptr.names[0].confirmed);
        }
      }
      source.ptr = ptrName || null;
      source.catalogue = matchCatalogue(source.ip, source.ptr);
      if (db) {
        const [seen] = db.ips({}, { ip: source.ip, limit: 1 });
        source.known = db.senderFor(source.ip, source.ptr);
        source.seen = seen ? { total: seen.total, failed: seen.failed, firstSeen: seen.firstSeen, lastSeen: seen.lastSeen } : null;
      }
      if (geoip && !source.private) {
        const geo = await geoip.lookup([source.ip]).then((m) => m.get(source.ip) || null).catch(() => null);
        if (geo && geo.source !== "none") source.geo = { country: geo.country || null, countryCode: geo.countryCode || null, city: geo.city || null, asn: geo.asn || null, asOrg: geo.asOrg || null };
      }
    }

    // --- transit time ---
    const dated = hops.filter((h) => h.date !== null);
    const transit = { totalSeconds: dated.length >= 2 ? dated[dated.length - 1].date - dated[0].date : null, slowest: null };
    for (const hop of hops) {
      if (hop.delaySeconds !== null && (!transit.slowest || hop.delaySeconds > transit.slowest.seconds)) transit.slowest = { index: hop.index, seconds: hop.delaySeconds, by: hop.by };
    }

    // --- plain-language findings ---
    const findings = [];
    const add = (severity, textLine) => findings.push({ severity, text: textLine });
    if (!top) add("warn", "No Authentication-Results header: the receiving server did not record SPF, DKIM or DMARC results, or these headers were copied before delivery. Alignment below is computed from what is there.");
    if (computedDmarc === "pass") add("good", `DMARC passes for ${fromDomain}: ${verdicts.dmarc.via.join(" and ")} ${verdicts.dmarc.via.length > 1 ? "are" : "is"} aligned with the From domain${dkimAlignedDomains.length ? ` (signed by ${[...new Set(dkimAlignedDomains)].join(", ")})` : ""}.`);
    if (computedDmarc === "fail") {
      const why = [];
      if (spfResult === "pass" && !spfAligned) why.push(`SPF passed for ${spfDomain}, which is not ${strictSpf ? "exactly" : "the same organisation as"} ${fromDomain}`);
      else if (spfResult) why.push(`SPF ${spfResult}${spfDomain ? ` for ${spfDomain}` : ""}`);
      else why.push("no SPF result");
      if (dkimPassing.length && !dkimAlignedDomains.length) why.push(`DKIM passed only for ${[...new Set(dkimPassing)].join(", ")}, not for ${fromDomain}`);
      else if (dkimAuth.length) why.push(`DKIM ${dkimAuth[0].result}`);
      else why.push(signatures.length ? "the DKIM signature was not evaluated" : "no DKIM signature");
      add("bad", `DMARC fails for ${fromDomain}: ${why.join("; ")}.`);
    }
    if (verdicts.dmarc.reported && computedDmarc && verdicts.dmarc.reported !== computedDmarc && !["bestguesspass", "none", "temperror", "permerror"].includes(verdicts.dmarc.reported)) {
      add("warn", `The receiver recorded dmarc=${verdicts.dmarc.reported}, but the SPF and DKIM results in the same header compute to ${computedDmarc}. An ARC override, a local policy or a strict-alignment tag may explain it.`);
    }
    if (dmarcRecord && !dmarcRecord.found && fromDomain) add("warn", `${fromDomain} publishes no DMARC record, so receivers apply no policy to mail that fails.`);
    else if (verdicts.dmarc.policy === "none" && computedDmarc === "fail") add("warn", `${fromDomain} has p=none: this failing message is delivered anyway.`);
    else if (verdicts.dmarc.policy && verdicts.dmarc.policy !== "none" && computedDmarc === "fail") add("bad", `${fromDomain} has p=${verdicts.dmarc.policy}: receivers that honour it ${verdicts.dmarc.policy === "reject" ? "reject" : "quarantine"} this message${verdicts.dmarc.action ? ` (this receiver applied action=${verdicts.dmarc.action})` : ""}.`);
    for (const sig of signatures) {
      const name = `${sig.selector || "?"}._domainkey.${sig.domain || "?"}`;
      if (sig.expired) add("warn", `The DKIM signature ${name} expired on ${new Date(sig.expiresAt * 1000).toISOString().slice(0, 10)} (x= tag).`);
      if (!sig.signsFrom) add("bad", `The DKIM signature ${name} does not cover the From header, so it proves nothing about the sender.`);
      if (sig.bodyLength !== null) add("warn", `The DKIM signature ${name} uses l=${sig.bodyLength}: only part of the body is signed, and text can be appended without breaking it.`);
      if (sig.dns && !sig.dns.found && !sig.dns.error) add(sig.result === "pass" ? "warn" : "bad", `No DKIM key is published at ${name} now${sig.result === "pass" ? " (it existed when the message was checked; the selector has been removed since)" : ""}.`);
      if (sig.dns && sig.dns.weak) add("warn", `The DKIM key at ${name} is only ${sig.dns.keyBits} bits.`);
      if (sig.result && sig.result !== "pass") add("bad", `DKIM ${sig.result} for ${name}${sig.resultComment ? ` (${sig.resultComment})` : ""}: the message was modified in transit, or the key does not match.`);
    }
    if (from && from.name && /[^\s<>"]+@[^\s<>"]+\.[a-z]{2,}/i.test(from.name) && !from.name.toLowerCase().includes(from.address || "\u0000")) {
      add("bad", `The display name shows a different address ("${from.name}") from the real one (${from.address}): a common way to disguise the sender.`);
    }
    if (replyTo && from && replyTo.domain && from.domain && orgDomain(replyTo.domain) !== orgDomain(from.domain)) add("warn", `Replies go to ${replyTo.address}, a different domain from the From address (${from.address}).`);
    if (returnPath && from && returnPath.domain && from.domain && orgDomain(returnPath.domain) !== orgDomain(from.domain)) add("info", `The envelope sender (${returnPath.address || returnPath.domain}) is in a different domain from the From address: normal for mail sent through a service, and the reason SPF alone does not align.`);
    if (verdicts.arc && verdicts.arc.sets) add(verdicts.arc.chain === "fail" ? "warn" : "info", `The message passed through ${verdicts.arc.sets} ARC-sealing intermediar${verdicts.arc.sets === 1 ? "y" : "ies"} (${[...new Set(verdicts.arc.seals.map((s) => s.domain).filter(Boolean))].join(", ") || "unnamed"}); the chain validation is ${verdicts.arc.chain || "unknown"}${verdicts.arc.result ? `, and the receiver recorded arc=${verdicts.arc.result}` : ""}. A forwarder or mailing list handled it.`);
    if (transit.totalSeconds !== null) {
      if (transit.totalSeconds < 0) add("warn", "The hop timestamps run backwards overall: a server clock on the path is wrong.");
      else if (transit.totalSeconds > 600) add("warn", `Delivery took ${formatDuration(transit.totalSeconds)}${transit.slowest && transit.slowest.seconds > 60 ? `; the longest wait was ${formatDuration(transit.slowest.seconds)} before hop ${transit.slowest.index}${transit.slowest.by ? ` (${transit.slowest.by})` : ""}` : ""}.`);
      else add("info", `Delivered in ${formatDuration(transit.totalSeconds)} over ${hops.length} hop${hops.length === 1 ? "" : "s"}.`);
    }
    if (hops.some((h) => h.delaySeconds !== null && h.delaySeconds < -5)) add("info", "At least one hop is stamped earlier than the one before it; small differences are clock drift between servers.");
    if (source.ip && !source.private) {
      const who = source.known ? `your known sender "${source.known.label}"` : source.catalogue ? `${source.catalogue.name}` : source.ptr || null;
      add(source.known ? "good" : "info", `Handed to the receiver by ${source.ip}${who ? ` (${who})` : " (no reverse DNS)"}${source.seen ? `; this address appears in your DMARC reports with ${source.seen.total} messages, ${source.seen.failed} failing` : db ? "; it does not appear in your stored DMARC reports" : ""}.`);
    }
    if (microsoft) {
      if (microsoft.compauth && microsoft.compauth.result !== "pass" && microsoft.compauth.meaning) add(microsoft.compauth.result === "fail" ? "bad" : "info", `Microsoft composite authentication: ${microsoft.compauth.result}${microsoft.compauth.reason ? ` (reason ${microsoft.compauth.reason})` : ""}: ${microsoft.compauth.meaning}.`);
      if (microsoft.cat && microsoft.cat !== "NONE") add("bad", `Microsoft 365 classified the message as ${microsoft.catMeaning || microsoft.cat} (CAT:${microsoft.cat}).`);
      if (microsoft.scl !== null && microsoft.scl >= 5) add("bad", `Spam confidence level ${microsoft.scl}: ${microsoft.sclMeaning}.`);
      if (microsoft.sfv && ["SKA", "SKN", "SFE", "SKI", "SKE"].includes(microsoft.sfv)) add("info", `Spam filtering was bypassed (SFV:${microsoft.sfv}: ${microsoft.sfvMeaning}).`);
      if (microsoft.sfv && ["SKB", "BLK", "SKS"].includes(microsoft.sfv)) add("warn", `Marked as spam by configuration, not by content (SFV:${microsoft.sfv}: ${microsoft.sfvMeaning}).`);
    }

    return {
      summary,
      verdicts,
      authResults: authHeaders,
      arcAuthResults: valuesOf(headers, "ARC-Authentication-Results").map(parseAuthResults),
      receivedSpf,
      signatures,
      dmarcRecord: dmarcRecord ? { found: Boolean(dmarcRecord.found), record: dmarcRecord.record || null, tags: dmarcRecord.tags || {}, inheritedFrom: dmarcRecord.inheritedFrom || null, error: dmarcRecord.error || null } : null,
      hops,
      transit,
      source: source.ip ? source : null,
      microsoft,
      otherFilters: parseOtherFilters(headers),
      findings,
      headers,
      counts: { headers: headers.length, hops: hops.length, signatures: signatures.length }
    };
  }

  return { analyze };
}

module.exports = { createHeaderAnalyzer, parseHeaderBlock, parseAddress, parseReceived, parseAuthResults, parseReceivedSpf, parseDkimSignature, findIps, isPrivateIp, compauthMeaning, formatDuration, MAX_INPUT_BYTES };
