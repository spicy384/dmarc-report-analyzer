/**
 * DNS lookups for the records DMARC depends on: the DMARC policy record, the SPF
 * record (expanded through includes to the networks it authorises) and DKIM
 * selector keys. Resolvers are injectable so tests run without the network.
 */
const dns = require("dns");

const SPF_LOOKUP_LIMIT = 10;
const MAX_DEPTH = 10;

function defaultResolvers({ timeoutMs }) {
  const r = new dns.promises.Resolver({ timeout: timeoutMs, tries: 2 });
  return {
    resolveTxt: (name) => r.resolveTxt(name),
    resolve4: (name) => r.resolve4(name),
    resolve6: (name) => r.resolve6(name),
    resolveMx: (name) => r.resolveMx(name)
  };
}

function isNotFound(error) {
  return error && (error.code === "ENOTFOUND" || error.code === "ENODATA" || error.code === "ESERVFAIL" && false);
}

/** Joins the chunks of each TXT record and returns plain strings. */
async function txtRecords(resolvers, name) {
  try {
    const rows = await resolvers.resolveTxt(name);
    return rows.map((chunks) => (Array.isArray(chunks) ? chunks.join("") : String(chunks)));
  } catch (error) {
    if (isNotFound(error)) {
      return [];
    }
    throw error;
  }
}

/** The registrable domain, naively: the last two labels (good enough for the common cases). */
function organizationalDomain(domain) {
  const labels = String(domain).toLowerCase().split(".").filter(Boolean);
  return labels.length <= 2 ? labels.join(".") : labels.slice(-2).join(".");
}

function parseDmarcTags(record) {
  const tags = {};
  for (const part of record.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (!key) continue;
    if (key === "rua" || key === "ruf") {
      tags[key] = value.split(",").map((s) => s.trim()).filter(Boolean).map((s) => s.replace(/^mailto:/i, "").replace(/!.*$/, ""));
    } else if (key === "pct" || key === "ri") {
      tags[key] = Number(value);
    } else {
      tags[key] = value.toLowerCase();
    }
  }
  return tags;
}

function createDnsRecords({ resolvers, timeoutMs = 5000, cacheTtlMs = 60 * 60 * 1000, now = Date.now } = {}) {
  const r = resolvers || defaultResolvers({ timeoutMs });
  const cache = new Map();

  async function cached(key, refresh, produce) {
    const hit = cache.get(key);
    if (hit && !refresh && now() - hit.at < cacheTtlMs) {
      return hit.value;
    }
    const value = await produce();
    cache.set(key, { value, at: now() });
    return value;
  }

  /** The DMARC record for a domain, falling back to the organizational domain like receivers do. */
  async function getDmarc(domain, { refresh = false } = {}) {
    const d = String(domain || "").trim().toLowerCase();
    return cached(`dmarc:${d}`, refresh, async () => {
      const tried = [d];
      let records = await txtRecords(r, `_dmarc.${d}`);
      let inheritedFrom = null;
      let dmarc = records.find((t) => /^v=dmarc1\b/i.test(t.trim()));
      if (!dmarc) {
        const org = organizationalDomain(d);
        if (org !== d) {
          tried.push(org);
          records = await txtRecords(r, `_dmarc.${org}`);
          dmarc = records.find((t) => /^v=dmarc1\b/i.test(t.trim()));
          if (dmarc) inheritedFrom = org;
        }
      }
      if (!dmarc) {
        return { domain: d, found: false, record: null, tags: {}, inheritedFrom: null, tried, warnings: ["No DMARC record found: receivers will not apply any policy and will not send reports."] };
      }
      const tags = parseDmarcTags(dmarc);
      const warnings = [];
      if (!tags.p) warnings.push("The record has no p= tag, so it is invalid and ignored by receivers.");
      if (tags.p === "none") warnings.push("p=none: receivers report but never quarantine or reject spoofed mail.");
      if (tags.pct !== undefined && tags.pct < 100) warnings.push(`pct=${tags.pct}: only ${tags.pct}% of failing mail gets the policy applied.`);
      if (tags.p && tags.p !== "none" && !tags.sp && !inheritedFrom) warnings.push("No sp= tag: subdomains inherit p=, which is fine, but set sp=reject explicitly if none of them should send mail.");
      if (!tags.rua || !tags.rua.length) warnings.push("No rua= address: nobody sends aggregate reports for this domain.");
      if (tags.adkim === "s") warnings.push("adkim=s: DKIM must be signed with exactly this domain; subdomain signatures will not align.");
      if (tags.aspf === "s") warnings.push("aspf=s: the envelope sender must be exactly this domain; subdomain senders will not align.");
      if (inheritedFrom) warnings.push(`No record at _dmarc.${d}; the policy of ${inheritedFrom} applies (sp= there, or p= if sp= is absent).`);
      return { domain: d, found: true, record: dmarc, tags, inheritedFrom, tried, warnings };
    });
  }

  /**
   * The SPF record for a domain, expanded through include:/redirect=/a/mx into the
   * networks it authorises. Counts DNS-querying mechanisms against the limit of 10.
   */
  async function getSpf(domain, { refresh = false } = {}) {
    const d = String(domain || "").trim().toLowerCase();
    return cached(`spf:${d}`, refresh, async () => {
      const state = { lookups: 0, networks: [], errors: [], includes: [], seen: new Set(), tooManyLookups: false };
      const record = await expand(d, d, 0, state);
      if (!record) {
        return { domain: d, found: false, record: null, ...summary(state), all: null, warnings: ["No SPF record found: receivers cannot verify which servers may send for this domain."] };
      }
      const allMatch = record.match(/(?:^|\s)([-~?+]?)all(?:\s|$)/i);
      const all = allMatch ? `${allMatch[1] || "+"}all` : null;
      const warnings = [];
      if (state.tooManyLookups) warnings.push(`More than ${SPF_LOOKUP_LIMIT} DNS lookups: receivers treat the record as a permanent error and SPF fails for everything.`);
      else if (state.lookups >= 8) warnings.push(`${state.lookups} of ${SPF_LOOKUP_LIMIT} DNS lookups used; adding another include may break SPF.`);
      if (!all) warnings.push("No all mechanism: anything not listed is treated as neutral.");
      else if (all === "+all") warnings.push("+all authorises every server on the internet; SPF is meaningless.");
      else if (all === "?all") warnings.push("?all is neutral: unlisted servers neither pass nor fail.");
      return { domain: d, found: true, record, ...summary(state), all, warnings };
    });
  }

  function summary(state) {
    return { networks: state.networks, lookups: state.lookups, tooManyLookups: state.tooManyLookups, includes: state.includes, errors: state.errors };
  }

  async function expand(domain, via, depth, state) {
    if (depth > MAX_DEPTH || state.seen.has(domain)) {
      if (state.seen.has(domain)) state.errors.push(`${domain} is included more than once (loop or duplicate).`);
      return null;
    }
    state.seen.add(domain);
    let records;
    try {
      records = await txtRecords(r, domain);
    } catch (error) {
      state.errors.push(`${domain}: ${error.code || error.message}`);
      return null;
    }
    const spf = records.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
    if (spf.length > 1) state.errors.push(`${domain} publishes ${spf.length} SPF records; receivers treat that as a permanent error.`);
    if (!spf.length) {
      if (depth > 0) state.errors.push(`${domain} (${via}) has no SPF record.`);
      return null;
    }
    const record = spf[0].trim();
    const label = depth === 0 ? "spf" : via;

    for (const raw of record.split(/\s+/).slice(1)) {
      const term = raw.replace(/^[-~?+]/, "");
      const lower = term.toLowerCase();
      const count = () => {
        state.lookups += 1;
        if (state.lookups > SPF_LOOKUP_LIMIT) {
          state.tooManyLookups = true;
          return false;
        }
        return true;
      };

      if (lower.startsWith("ip4:")) {
        state.networks.push({ cidr: term.slice(4), via: label });
      } else if (lower.startsWith("ip6:")) {
        state.networks.push({ cidr: term.slice(4), via: label });
      } else if (lower === "a" || lower.startsWith("a:") || lower.startsWith("a/")) {
        if (!count()) break;
        const spec = term.length > 1 ? term.slice(2) : domain;
        const [host, mask] = (lower.startsWith("a/") ? `${domain}${term.slice(1)}` : spec).split("/");
        await addHostNetworks(host || domain, mask, `${label} a:${host || domain}`, state);
      } else if (lower === "mx" || lower.startsWith("mx:") || lower.startsWith("mx/")) {
        if (!count()) break;
        const [host, mask] = (lower.startsWith("mx/") ? `${domain}${term.slice(2)}` : term.length > 2 ? term.slice(3) : domain).split("/");
        try {
          const mxs = await r.resolveMx(host || domain);
          for (const mx of mxs.slice(0, 10)) {
            await addHostNetworks(mx.exchange, mask, `${label} mx:${mx.exchange}`, state);
          }
        } catch (error) {
          state.errors.push(`mx ${host || domain}: ${error.code || error.message}`);
        }
      } else if (lower.startsWith("include:")) {
        if (!count()) break;
        const inc = term.slice(8);
        state.includes.push({ domain: inc, via: label });
        await expand(inc, `include:${inc}`, depth + 1, state);
      } else if (lower.startsWith("redirect=")) {
        if (!count()) break;
        const target = term.slice(9);
        state.includes.push({ domain: target, via: `${label} redirect` });
        await expand(target, `redirect=${target}`, depth + 1, state);
      } else if (lower.startsWith("exists:") || lower === "ptr" || lower.startsWith("ptr:")) {
        if (!count()) break;
        if (lower.startsWith("ptr")) state.errors.push("ptr mechanism is deprecated and slow; receivers may ignore it.");
      }
      // "all", "exp=" and unknown modifiers need no lookup.
    }
    return record;
  }

  async function addHostNetworks(host, mask, via, state) {
    const [v4, v6] = await Promise.all([
      r.resolve4(host).catch(() => []),
      r.resolve6(host).catch(() => [])
    ]);
    for (const ip of v4) state.networks.push({ cidr: mask ? `${ip}/${mask}` : ip, via });
    for (const ip of v6) state.networks.push({ cidr: mask ? `${ip}/${mask}` : ip, via });
    if (!v4.length && !v6.length) state.errors.push(`${host} has no A or AAAA record.`);
  }

  /** Whether a DKIM selector publishes a key for the domain. */
  async function checkDkim(domain, selector, { refresh = false } = {}) {
    const d = String(domain || "").trim().toLowerCase();
    const s = String(selector || "").trim();
    return cached(`dkim:${s}:${d}`, refresh, async () => {
      const name = `${s}._domainkey.${d}`;
      let records;
      try {
        records = await txtRecords(r, name);
      } catch (error) {
        return { domain: d, selector: s, name, found: false, error: error.code || error.message };
      }
      const record = records.find((t) => /(^|;)\s*p=/i.test(t)) || records[0] || null;
      if (!record) {
        return { domain: d, selector: s, name, found: false };
      }
      const p = (record.match(/(?:^|;)\s*p=([^;]*)/i) || [])[1];
      const k = (record.match(/(?:^|;)\s*k=([^;]*)/i) || [])[1];
      return { domain: d, selector: s, name, found: true, record, keyType: (k || "rsa").trim(), revoked: p !== undefined && p.trim() === "" };
    });
  }

  function clearCache() {
    cache.clear();
  }

  return { getDmarc, getSpf, checkDkim, clearCache, organizationalDomain, parseDmarcTags };
}

module.exports = { createDnsRecords, organizationalDomain, parseDmarcTags, SPF_LOOKUP_LIMIT };
