/**
 * Country, city and network (ASN) for source IPs. Two sources, files preferred:
 *   - MaxMind GeoLite2-City.mmdb and GeoLite2-ASN.mmdb read locally (no IP leaves the host)
 *   - ip-api.com's batch endpoint for whatever the files cannot answer (HTTP only,
 *     100 IPs per request, 15 requests per minute, free tier is for non-commercial use)
 * Results are cached in ip_info by the caller.
 */
const fs = require("fs");
const path = require("path");
const { parseIp, parseCidr, cidrContains } = require("./ipmatch");

const BATCH_SIZE = 100;
const ONLINE_MIN_INTERVAL_MS = 4100; // 15 requests per minute with a little headroom
const DEFAULT_ONLINE_BASE = "http://ip-api.com";

// Ranges no public database knows anything about; asking about them wastes quota.
const PRIVATE = [
  "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
  "0.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
  "::1/128", "fc00::/7", "fe80::/10", "2001:db8::/32", "::/128"
].map(parseCidr);

function isPrivate(ip) {
  const parsed = parseIp(ip);
  if (!parsed) {
    return true;
  }
  return PRIVATE.some((c) => cidrContains(c, parsed));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Splits "AS13335 Cloudflare, Inc." into { asn: 13335, asOrg: "Cloudflare, Inc." }. */
function parseAsField(text) {
  const m = /^AS(\d+)\s*(.*)$/.exec(String(text || "").trim());
  if (!m) {
    return { asn: null, asOrg: String(text || "").trim() || null };
  }
  return { asn: Number(m[1]), asOrg: m[2].trim() || null };
}

function createGeoIp({
  dataDir,
  cityDb,
  asnDb,
  online = true,
  onlineBase = DEFAULT_ONLINE_BASE,
  fetchImpl = globalThis.fetch,
  readers = null,
  logger = console,
  minIntervalMs = ONLINE_MIN_INTERVAL_MS
} = {}) {
  const cityPath = cityDb || (dataDir ? path.join(dataDir, "geoip", "GeoLite2-City.mmdb") : null);
  const asnPath = asnDb || (dataDir ? path.join(dataDir, "geoip", "GeoLite2-ASN.mmdb") : null);
  let city = readers ? readers.city || null : null;
  let asn = readers ? readers.asn || null : null;
  let opened = Boolean(readers);
  let lastOnlineAt = 0;
  const problems = [];

  async function open() {
    if (opened) {
      return describe();
    }
    opened = true;
    let maxmind = null;
    for (const [label, file, assign] of [["city", cityPath, (r) => { city = r; }], ["asn", asnPath, (r) => { asn = r; }]]) {
      if (!file || !fs.existsSync(file)) {
        continue;
      }
      try {
        maxmind = maxmind || require("maxmind");
        assign(await maxmind.open(file));
        logger.log?.(`geoip: using ${file}`);
      } catch (error) {
        problems.push(`${label}: ${file}: ${error.message}`);
        logger.warn?.(`geoip: could not open ${file}: ${error.message}`);
      }
    }
    return describe();
  }

  function describe() {
    return {
      cityDb: city ? cityPath || "injected" : null,
      asnDb: asn ? asnPath || "injected" : null,
      cityPath,
      asnPath,
      online: Boolean(online),
      onlineProvider: online ? new URL(onlineBase).host : null,
      problems
    };
  }

  function fromFiles(ip) {
    const out = { countryCode: null, country: null, city: null, asn: null, asOrg: null, source: null };
    let any = false;
    if (city) {
      const r = city.get(ip);
      if (r) {
        out.countryCode = r.country?.iso_code || r.registered_country?.iso_code || null;
        out.country = r.country?.names?.en || r.registered_country?.names?.en || null;
        out.city = r.city?.names?.en || null;
        any = any || Boolean(out.countryCode);
      }
    }
    if (asn) {
      const r = asn.get(ip);
      if (r) {
        out.asn = r.autonomous_system_number || null;
        out.asOrg = r.autonomous_system_organization || null;
        any = any || Boolean(out.asn);
      }
    }
    out.source = any ? "file" : null;
    return any ? out : null;
  }

  async function fromOnline(ips) {
    const results = new Map();
    for (let i = 0; i < ips.length; i += BATCH_SIZE) {
      const batch = ips.slice(i, i + BATCH_SIZE);
      const wait = lastOnlineAt + minIntervalMs - Date.now();
      if (wait > 0) {
        await sleep(wait);
      }
      lastOnlineAt = Date.now();
      let res;
      try {
        res = await fetchImpl(`${onlineBase}/batch?fields=status,message,query,countryCode,country,city,as`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(batch)
        });
      } catch (error) {
        logger.warn?.(`geoip: online lookup failed: ${error.message}`);
        break;
      }
      if (res.status === 429) {
        logger.warn?.("geoip: online lookup throttled; the rest will be tried after the next sync");
        break;
      }
      if (!res.ok) {
        logger.warn?.(`geoip: online lookup answered ${res.status}`);
        break;
      }
      const rows = await res.json().catch(() => []);
      for (const row of Array.isArray(rows) ? rows : []) {
        if (!row || row.status !== "success" || !row.query) {
          continue;
        }
        const { asn: number, asOrg } = parseAsField(row.as);
        results.set(row.query, {
          countryCode: row.countryCode || null,
          country: row.country || null,
          city: row.city || null,
          asn: number,
          asOrg,
          source: "online"
        });
      }
    }
    return results;
  }

  /**
   * Looks up a list of IPs. Returns a Map of ip -> info; IPs that could not be
   * resolved by any source map to { source: "none" } so the caller can cache the miss.
   */
  async function lookup(ips) {
    await open();
    const out = new Map();
    const pending = [];
    for (const ip of ips) {
      if (isPrivate(ip)) {
        out.set(ip, { countryCode: null, country: null, city: null, asn: null, asOrg: null, source: "none" });
        continue;
      }
      const hit = fromFiles(ip);
      if (hit && (hit.countryCode || !city) && (hit.asn || !asn)) {
        out.set(ip, hit);
      } else if (online) {
        pending.push(ip);
        if (hit) out.set(ip, hit); // partial answer from files, may be improved online
      } else {
        out.set(ip, hit || { countryCode: null, country: null, city: null, asn: null, asOrg: null, source: "none" });
      }
    }
    if (pending.length) {
      const online2 = await fromOnline(pending);
      for (const ip of pending) {
        const found = online2.get(ip);
        if (found) {
          const partial = out.get(ip);
          out.set(ip, partial ? { ...found, ...Object.fromEntries(Object.entries(partial).filter(([k, v]) => v && k !== "source")), source: "file+online" } : found);
        } else if (!out.has(ip)) {
          // Left unresolved on purpose (no entry) when the online service failed, so it is retried later.
        }
      }
    }
    return out;
  }

  function isEnabled() {
    return Boolean(city || asn || online);
  }

  return { open, describe, lookup, isEnabled, isPrivate, parseAsField };
}

/** Flag emoji for a two-letter country code. */
function flagEmoji(countryCode) {
  const cc = String(countryCode || "").toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) {
    return "";
  }
  return String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

module.exports = { createGeoIp, isPrivate, parseAsField, flagEmoji, BATCH_SIZE };
