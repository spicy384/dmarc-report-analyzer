/** DMARC / SPF / DKIM record lookups against an in-memory resolver. */
const { createChecker } = require("./helpers/assert");
const { createDnsRecords, organizationalDomain, parseDmarcTags } = require("../dns-records");

const { check, report } = createChecker("dns-records: DMARC, SPF expansion, DKIM");

const zone = {
  txt: {
    "_dmarc.example.com": [["v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@example.com,mailto:x@agg.test!10m; adkim=r; aspf=r"]],
    "_dmarc.none.test": [["v=DMARC1; p=none; rua=mailto:r@none.test"]],
    "_dmarc.bad.test": [["v=DMARC1; pct=50"]],
    "example.com": [["v=spf1 ip4:203.0.113.0/24 include:spf.protection.outlook.com include:_spf.google.com a mx -all"], ["some other txt"]],
    "spf.protection.outlook.com": [["v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ip6:2a01:111:f400::/48 -all"]],
    "_spf.google.com": [["v=spf1 include:_netblocks.google.com ~all"]],
    "_netblocks.google.com": [["v=spf1 ip4:209.85.128.0/17 ~all"]],
    "loop.test": [["v=spf1 include:loop2.test -all"]],
    "loop2.test": [["v=spf1 include:loop.test include:loop.test -all"]],
    "many.test": [["v=spf1 " + Array.from({ length: 12 }, (_, i) => `include:inc${i}.test`).join(" ") + " -all"]],
    "double.test": [["v=spf1 -all"], ["v=spf1 ip4:1.1.1.1 -all"]],
    "s1._domainkey.example.com": [["v=DKIM1; k=rsa; p=MIIBIjANBgkq"]],
    "old._domainkey.example.com": [["v=DKIM1; p="]]
  },
  a: { "example.com": ["198.51.100.5"], "mx1.example.com": ["198.51.100.10"] },
  aaaa: { "example.com": ["2001:db8::5"] },
  mx: { "example.com": [{ exchange: "mx1.example.com", priority: 10 }] }
};
for (let i = 0; i < 12; i += 1) zone.txt[`inc${i}.test`] = [[`v=spf1 ip4:10.${i}.0.0/16 -all`]];

const notFound = () => { const e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e; };
let calls = 0;
const resolvers = {
  resolveTxt: async (name) => { calls += 1; return zone.txt[name] || notFound(); },
  resolve4: async (name) => zone.a[name] || notFound(),
  resolve6: async (name) => zone.aaaa[name] || notFound(),
  resolveMx: async (name) => zone.mx[name] || notFound()
};

let clock = 1000;
const dnsr = createDnsRecords({ resolvers, now: () => clock, cacheTtlMs: 1000 });

(async () => {
  // --- helpers ---
  check("organizationalDomain", organizationalDomain("mail.shop.example.com") === "example.com" && organizationalDomain("example.com") === "example.com");
  const tags = parseDmarcTags("v=DMARC1; p=Reject ; rua=mailto:a@b.test, mailto:c@d.test!10m; pct=50");
  check("parseDmarcTags", tags.p === "reject" && tags.rua.join(",") === "a@b.test,c@d.test" && tags.pct === 50);

  // --- dmarc ---
  const d = await dnsr.getDmarc("example.com");
  check("dmarc: found and parsed", d.found && d.tags.p === "quarantine" && d.tags.sp === "reject" && d.tags.rua.length === 2 && d.inheritedFrom === null);
  check("dmarc: no warnings for a sound record", d.warnings.length === 0, JSON.stringify(d.warnings));
  const sub = await dnsr.getDmarc("shop.example.com");
  check("dmarc: subdomain inherits the org record", sub.found && sub.inheritedFrom === "example.com" && sub.warnings.some((w) => /policy of example.com/.test(w)));
  const none = await dnsr.getDmarc("none.test");
  check("dmarc: p=none warning", none.warnings.some((w) => /p=none/.test(w)));
  const bad = await dnsr.getDmarc("bad.test");
  check("dmarc: missing p and pct<100 warnings", bad.warnings.some((w) => /no p=/.test(w)) && bad.warnings.some((w) => /pct=50/.test(w)) && bad.warnings.some((w) => /rua/.test(w)));
  const missing = await dnsr.getDmarc("nothing.test");
  check("dmarc: absent", missing.found === false && missing.tried.length === 1 && missing.warnings.length === 1);

  // --- spf ---
  const spf = await dnsr.getSpf("example.com");
  check("spf: record found", spf.found && spf.record.startsWith("v=spf1") && spf.all === "-all");
  const cidrs = spf.networks.map((n) => n.cidr);
  check("spf: direct ip4", cidrs.includes("203.0.113.0/24"));
  check("spf: nested includes expanded", cidrs.includes("40.107.0.0/16") && cidrs.includes("2a01:111:f400::/48") && cidrs.includes("209.85.128.0/17"));
  check("spf: via labels", spf.networks.find((n) => n.cidr === "40.107.0.0/16").via === "include:spf.protection.outlook.com");
  check("spf: a and mx resolved", cidrs.includes("198.51.100.5") && cidrs.includes("2001:db8::5") && cidrs.includes("198.51.100.10"));
  check("spf: lookups counted (2 includes + 1 nested + a + mx = 5)", spf.lookups === 5 && spf.tooManyLookups === false, String(spf.lookups));
  check("spf: includes listed", spf.includes.length === 3);
  check("spf: no warnings", spf.warnings.length === 0, JSON.stringify(spf.warnings));

  const loop = await dnsr.getSpf("loop.test");
  check("spf: include loops are caught", loop.found && loop.errors.some((e) => /more than once/.test(e)));
  const many = await dnsr.getSpf("many.test");
  check("spf: lookup limit", many.tooManyLookups && many.warnings.some((w) => /More than 10/.test(w)) && many.lookups === 11);
  const dbl = await dnsr.getSpf("double.test");
  check("spf: two records flagged", dbl.errors.some((e) => /2 SPF records/.test(e)));
  const nospf = await dnsr.getSpf("nothing.test");
  check("spf: absent", nospf.found === false && nospf.warnings.length === 1);

  // --- dkim ---
  const k = await dnsr.checkDkim("example.com", "s1");
  check("dkim: key found", k.found && k.keyType === "rsa" && k.revoked === false && k.name === "s1._domainkey.example.com");
  const revoked = await dnsr.checkDkim("example.com", "old");
  check("dkim: revoked key", revoked.found && revoked.revoked === true);
  const nok = await dnsr.checkDkim("example.com", "nope");
  check("dkim: missing selector", nok.found === false);

  // --- cache ---
  const before = calls;
  await dnsr.getDmarc("example.com");
  check("cache: second call hits the cache", calls === before);
  clock += 2000;
  await dnsr.getDmarc("example.com");
  check("cache: expires", calls === before + 1);
  await dnsr.getDmarc("example.com", { refresh: true });
  check("cache: refresh bypasses", calls === before + 2);

  process.exit(report() ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(1); });
