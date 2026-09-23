/** GeoIP: file readers (stubbed), online batch lookups (mock server), private ranges, merging. */
const http = require("http");
const { createChecker } = require("./helpers/assert");
const { createGeoIp, isPrivate, parseAsField, flagEmoji } = require("../geoip");

const { check, report } = createChecker("GeoIP: files, online fallback, private ranges");

check("private ranges", isPrivate("10.1.2.3") && isPrivate("192.168.0.1") && isPrivate("2001:db8::1") && isPrivate("::1") && isPrivate("not-an-ip") && !isPrivate("8.8.8.8") && !isPrivate("2a01:111:f400::1"));
check("parseAsField", parseAsField("AS13335 Cloudflare, Inc.").asn === 13335 && parseAsField("AS13335 Cloudflare, Inc.").asOrg === "Cloudflare, Inc." && parseAsField("").asn === null);
check("flagEmoji", flagEmoji("de") === "\u{1F1E9}\u{1F1EA}" && flagEmoji("") === "" && flagEmoji("xyz") === "");

// --- online mock ----------------------------------------------------------------
const seen = [];
let throttle = false;
const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => { body += c; });
  req.on("end", () => {
    const ips = JSON.parse(body || "[]");
    seen.push(ips);
    if (throttle) {
      res.writeHead(429);
      return res.end();
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(ips.map((ip) => ip === "203.0.113.200"
      ? { status: "fail", message: "reserved range", query: ip }
      : { status: "success", query: ip, countryCode: "DE", country: "Germany", city: "Berlin", as: "AS3320 Deutsche Telekom AG" })));
  });
});

(async () => {
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const quiet = { log() {}, warn() {}, error() {} };

  // --- files only (stub readers) ---
  const cityReader = { get: (ip) => (ip === "40.107.22.51" ? { country: { iso_code: "US", names: { en: "United States" } }, city: { names: { en: "Redmond" } } } : null) };
  const asnReader = { get: (ip) => (ip === "40.107.22.51" ? { autonomous_system_number: 8075, autonomous_system_organization: "Microsoft Corporation" } : null) };
  const filesOnly = createGeoIp({ readers: { city: cityReader, asn: asnReader }, online: false, logger: quiet });
  const f = await filesOnly.lookup(["40.107.22.51", "185.220.101.7", "10.0.0.1"]);
  check("files: full hit", f.get("40.107.22.51").countryCode === "US" && f.get("40.107.22.51").city === "Redmond" && f.get("40.107.22.51").asn === 8075 && f.get("40.107.22.51").source === "file");
  check("files: miss without online is cached as none", f.get("185.220.101.7").source === "none" && f.get("185.220.101.7").countryCode === null);
  check("files: private is none", f.get("10.0.0.1").source === "none");
  check("describe reports readers", filesOnly.describe().cityDb === "injected" && filesOnly.describe().online === false);

  // --- online only ---
  const onlineOnly = createGeoIp({ online: true, onlineBase: base, logger: quiet, minIntervalMs: 0 });
  const o = await onlineOnly.lookup(["185.220.101.7", "203.0.113.200", "192.168.1.1", "2a01:111:f400::1"]);
  check("online: resolved", o.get("185.220.101.7").countryCode === "DE" && o.get("185.220.101.7").asn === 3320 && o.get("185.220.101.7").asOrg === "Deutsche Telekom AG" && o.get("185.220.101.7").source === "online");
  check("online: private never sent", !seen.flat().includes("192.168.1.1") && o.get("192.168.1.1").source === "none");
  check("online: documentation range never sent (203.0.113.0/24 is reserved)", !seen.flat().includes("203.0.113.200"));
  check("online: v6 sent", seen.flat().includes("2a01:111:f400::1"));
  check("describe reports provider", onlineOnly.describe().onlineProvider === `127.0.0.1:${server.address().port}`);

  // --- files preferred, online fills the gaps ---
  const both = createGeoIp({ readers: { city: cityReader, asn: null }, online: true, onlineBase: base, logger: quiet, minIntervalMs: 0 });
  seen.length = 0;
  const b = await both.lookup(["40.107.22.51", "8.8.8.8"]);
  check("both: file answers are not sent online when complete for the readers present", !seen.flat().includes("40.107.22.51") && b.get("40.107.22.51").source === "file");
  check("both: gaps go online", seen.flat().includes("8.8.8.8") && b.get("8.8.8.8").source === "online");

  // --- batching and throttling ---
  seen.length = 0;
  const many = Array.from({ length: 150 }, (_, i) => `45.83.${64 + Math.floor(i / 250)}.${i + 1}`);
  const m = await onlineOnly.lookup(many);
  check("online: batches of 100", seen.length === 2 && seen[0].length === 100 && seen[1].length === 50 && m.size === 150);
  throttle = true;
  seen.length = 0;
  const t = await onlineOnly.lookup(["8.8.4.4"]);
  check("online: 429 leaves the ip unresolved for a later retry", t.size === 0 && seen.length === 1);
  throttle = false;

  // --- missing files are tolerated ---
  const noFiles = createGeoIp({ dataDir: "C:/definitely/not/here", online: false, logger: quiet });
  const d = await noFiles.open();
  check("missing files: no readers, no problems reported", d.cityDb === null && d.asnDb === null && d.problems.length === 0 && noFiles.isEnabled() === false);

  // No process.exit here: on Windows, exiting while undici's keep-alive sockets are
  // still closing trips a libuv assertion. Let the loop drain instead.
  process.exitCode = report() ? 0 : 1;
  server.closeAllConnections?.();
  server.close();
})().catch((e) => { console.error(e); process.exit(1); });
