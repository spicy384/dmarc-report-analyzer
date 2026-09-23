/**
 * Matching source IPs against "known sender" patterns: a single IP, a CIDR
 * block (IPv4 or IPv6) or a reverse-DNS name, exact or with a leading "*."
 * wildcard. Pure functions, no I/O.
 */

const V4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function parseV4(text) {
  const m = V4_RE.exec(text);
  if (!m) {
    return null;
  }
  let value = 0n;
  for (let i = 1; i <= 4; i += 1) {
    const octet = Number(m[i]);
    if (octet > 255) {
      return null;
    }
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

function parseV6(text) {
  let s = text.toLowerCase();
  if (s.includes("%")) {
    s = s.slice(0, s.indexOf("%")); // zone id
  }
  // Embedded IPv4 in the last 32 bits (::ffff:1.2.3.4).
  const lastColon = s.lastIndexOf(":");
  if (lastColon >= 0 && s.slice(lastColon + 1).includes(".")) {
    const v4 = parseV4(s.slice(lastColon + 1));
    if (v4 === null) {
      return null;
    }
    const hi = (v4 >> 16n).toString(16);
    const lo = (v4 & 0xffffn).toString(16);
    s = `${s.slice(0, lastColon + 1)}${hi}:${lo}`;
  }
  const parts = s.split("::");
  if (parts.length > 2) {
    return null;
  }
  const head = parts[0] ? parts[0].split(":") : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (parts.length === 1 && missing !== 0)) {
    return null;
  }
  const groups = [...head, ...Array(parts.length === 2 ? missing : 0).fill("0"), ...tail];
  if (groups.length !== 8) {
    return null;
  }
  let value = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) {
      return null;
    }
    value = (value << 16n) | BigInt(parseInt(g, 16));
  }
  return value;
}

/** Returns { version: 4 | 6, value: BigInt } or null. */
function parseIp(text) {
  const s = String(text || "").trim();
  if (!s) {
    return null;
  }
  const v4 = parseV4(s);
  if (v4 !== null) {
    return { version: 4, value: v4 };
  }
  if (s.includes(":")) {
    const v6 = parseV6(s);
    if (v6 !== null) {
      return { version: 6, value: v6 };
    }
  }
  return null;
}

/** Returns { version, network: BigInt, bits } for "a.b.c.d/nn", "x::/nn" or a bare address. */
function parseCidr(text) {
  const s = String(text || "").trim();
  const slash = s.indexOf("/");
  const ip = parseIp(slash >= 0 ? s.slice(0, slash) : s);
  if (!ip) {
    return null;
  }
  const max = ip.version === 4 ? 32 : 128;
  let bits = max;
  if (slash >= 0) {
    const n = s.slice(slash + 1);
    if (!/^\d{1,3}$/.test(n)) {
      return null;
    }
    bits = Number(n);
    if (bits > max) {
      return null;
    }
  }
  const mask = bits === 0 ? 0n : ((1n << BigInt(max)) - 1n) ^ ((1n << BigInt(max - bits)) - 1n);
  return { version: ip.version, network: ip.value & mask, bits, mask };
}

function cidrContains(cidr, ip) {
  return Boolean(cidr && ip && cidr.version === ip.version && (ip.value & cidr.mask) === cidr.network);
}

/**
 * Classifies a pattern:
 *   { type: "cidr", cidr }            an IP or CIDR block
 *   { type: "suffix", host }          "*.example.com"  (matches example.com and anything under it)
 *   { type: "host", host }            "mail.example.com"
 * Returns null when the pattern is none of those.
 */
function parsePattern(text) {
  const s = String(text || "").trim().toLowerCase();
  if (!s) {
    return null;
  }
  const cidr = parseCidr(s);
  if (cidr) {
    return { type: "cidr", cidr, pattern: s };
  }
  const HOST = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?\.)+[a-z0-9-]{2,}$/;
  if (s.startsWith("*.")) {
    const host = s.slice(2);
    return HOST.test(host) ? { type: "suffix", host, pattern: s } : null;
  }
  return HOST.test(s) ? { type: "host", host: s, pattern: s } : null;
}

/** Specificity used to pick the best of several matches: exact IP beats a /16 beats a wildcard host. */
function specificity(parsed) {
  if (parsed.type === "cidr") {
    return parsed.cidr.version === 4 ? parsed.cidr.bits * 4 : parsed.cidr.bits;
  }
  return parsed.type === "host" ? 1000 : 500 + parsed.host.split(".").length;
}

/** Pre-parses a list of { pattern, ... } rows; invalid patterns are dropped. */
function compileSenders(rows) {
  const out = [];
  for (const row of rows || []) {
    const parsed = parsePattern(row.pattern);
    if (parsed) {
      out.push({ row, parsed, rank: specificity(parsed) });
    }
  }
  out.sort((a, b) => b.rank - a.rank);
  return out;
}

function matches(parsed, ip, ptr) {
  if (parsed.type === "cidr") {
    return cidrContains(parsed.cidr, ip);
  }
  const host = String(ptr || "").toLowerCase().replace(/\.$/, "");
  if (!host) {
    return false;
  }
  if (parsed.type === "host") {
    return host === parsed.host;
  }
  return host === parsed.host || host.endsWith(`.${parsed.host}`);
}

/** The most specific known sender matching an IP (and its reverse-DNS name), or null. */
function findSender(compiled, ipText, ptr) {
  const ip = parseIp(ipText);
  for (const entry of compiled) {
    if (matches(entry.parsed, ip, ptr)) {
      return entry.row;
    }
  }
  return null;
}

module.exports = { parseIp, parseCidr, cidrContains, parsePattern, compileSenders, findSender, specificity };
