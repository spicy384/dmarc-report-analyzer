/** GeoIP set-up from Settings: MaxMind download, upload, validation, online toggle, scheduling. */
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const { createChecker } = require("./helpers/assert");
const { openDatabase } = require("../db");
const { tarPack } = require("../backup");
const { createGeoIpUpdater, extractDatabase, kindOf } = require("../geoip-update");

const { check, report } = createChecker("GeoIP updater: MaxMind download, upload, settings");

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-geoup-"));
const cityPath = path.join(dir, "geoip", "GeoLite2-City.mmdb");
const asnPath = path.join(dir, "geoip", "GeoLite2-ASN.mmdb");

// A stand-in for the maxmind reader: fake databases are "FAKE:<type>:<build epoch>".
const fakeDb = (type, built) => Buffer.from(`FAKE:${type}:${built}`);
const validate = (buffer) => {
  const m = buffer.toString("utf8").match(/^FAKE:([^:]+):(\d+)$/);
  if (!m) throw new Error("Unknown type of the database");
  return { databaseType: m[1], builtAt: Number(m[2]) };
};
// A stand-in for geoip.js that reports what is on disk.
let reloads = 0;
const geoip = {
  describe: () => {
    const info = (file) => (fs.existsSync(file) ? { path: file, bytes: fs.statSync(file).size, modifiedAt: 1, builtAt: validate(fs.readFileSync(file)).builtAt, type: validate(fs.readFileSync(file)).databaseType, loaded: true } : null);
    return { cityPath, asnPath, cityFile: info(cityPath), asnFile: info(asnPath), onlineProvider: "ip-api.com", problems: [] };
  },
  reload: async () => { reloads += 1; }
};
const archive = (type, built) => zlib.gzipSync(tarPack({ [`${type}_20260930/COPYRIGHT.txt`]: Buffer.from("c"), [`${type}_20260930/${type}.mmdb`]: fakeDb(type, built) }));

// A fake MaxMind: Basic auth 123456:goodkey, HEAD gives Last-Modified, GET gives the archive.
const maxmind = { calls: [], lastModified: "Tue, 29 Sep 2026 12:00:00 GMT", built: 1790000000, status: null };
const fetchImpl = async (url, options = {}) => {
  const method = options.method || "GET";
  const auth = Buffer.from(String(options.headers.Authorization || "").replace(/^Basic /, ""), "base64").toString();
  maxmind.calls.push(`${method} ${url.replace("https://mm.test/", "")} ${auth}`);
  const headers = { get: (h) => (h.toLowerCase() === "last-modified" ? maxmind.lastModified : null) };
  if (maxmind.status) return { ok: false, status: maxmind.status, headers };
  if (auth !== "123456:goodkey123") return { ok: false, status: 401, headers };
  const edition = url.match(/\/(GeoLite2-[A-Za-z]+)\/download/)[1];
  if (method === "HEAD") return { ok: true, status: 200, headers };
  const body = archive(edition, maxmind.built);
  return { ok: true, status: 200, headers, arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) };
};

let clock = Date.parse("2026-10-01T00:00:00Z");
const db = openDatabase({ file: ":memory:" });
const updated = [];
const updater = createGeoIpUpdater({ db, geoip, fetchImpl, validate, now: () => clock, logger: { log() {}, warn() {} }, onUpdated: (list) => updated.push(list.map((r) => r.kind).join("+")), onlineDefault: true, downloadBase: "https://mm.test" });

(async () => {
  // --- helpers ---
  check("kindOf: City, ASN, ISP and the rest", kindOf("GeoLite2-City") === "city" && kindOf("GeoIP2-City") === "city" && kindOf("GeoLite2-ASN") === "asn" && kindOf("GeoIP2-ISP") === "asn" && kindOf("GeoLite2-Country") === null);
  check("extractDatabase: bare file, gzip, and MaxMind's tar.gz", extractDatabase(fakeDb("X", 1)).toString() === "FAKE:X:1" && extractDatabase(zlib.gzipSync(fakeDb("X", 2))).toString() === "FAKE:X:2" && extractDatabase(archive("GeoLite2-City", 3)).toString() === "FAKE:GeoLite2-City:3");
  let threw = null;
  try { extractDatabase(zlib.gzipSync(tarPack({ "readme.txt": Buffer.from("x".repeat(600)) }))); } catch (e) { threw = e; }
  check("extractDatabase: an archive without a database is refused", threw && threw.status === 400);

  // --- settings ---
  const d0 = updater.describe();
  check("describe: nothing configured, online from the environment default", d0.accountId === "" && d0.hasLicenseKey === false && d0.autoUpdate === true && d0.online === true && d0.onlineSource === "environment" && d0.files.city === null && d0.nextUpdateAt === null);
  const bad = (patch) => { try { updater.save(patch); return null; } catch (e) { return e; } };
  check("save: account ID must be a number, key must look like one", bad({ accountId: "abc" }).status === 400 && bad({ licenseKey: "has space in it" }).status === 400 && bad({ licenseKey: "short" }).status === 400);
  const saved = updater.save({ accountId: "123456", licenseKey: "goodkey123", autoUpdate: true });
  check("save: stored, and the key never comes back", saved.accountId === "123456" && saved.hasLicenseKey === true && !JSON.stringify(saved).includes("goodkey123"));
  check("save: a blank key keeps the stored one", updater.save({ accountId: "123456", licenseKey: "" }).hasLicenseKey === true);
  check("online toggle overrides the environment default", updater.save({ online: false }).online === false && updater.describe().onlineSource === "setting" && updater.onlineEnabled() === false && updater.save({ online: true }).online === true);
  check("due: credentials set and never updated", updater.due() === true);

  // --- download ---
  const first = await updater.download();
  check("download: HEAD then GET for each edition, with the credentials", maxmind.calls.join(" | ") === "HEAD GeoLite2-City/download?suffix=tar.gz 123456:goodkey123 | GET GeoLite2-City/download?suffix=tar.gz 123456:goodkey123 | HEAD GeoLite2-ASN/download?suffix=tar.gz 123456:goodkey123 | GET GeoLite2-ASN/download?suffix=tar.gz 123456:goodkey123", maxmind.calls.join(" | "));
  check("download: both files installed, readers reopened, callback told", first.changed === 2 && fs.readFileSync(cityPath, "utf8") === "FAKE:GeoLite2-City:1790000000" && fs.readFileSync(asnPath, "utf8") === "FAKE:GeoLite2-ASN:1790000000" && reloads === 1 && updated.join() === "city+asn" && first.status.files.city.builtAt === 1790000000);
  check("download: outcome recorded, next check in a week", first.status.lastUpdate.ok === true && /Downloaded GeoLite2-City and GeoLite2-ASN/.test(first.status.lastUpdate.detail) && first.status.nextUpdateAt === Math.floor((clock + 7 * 86400000) / 1000) && updater.due() === false);
  check("no temporary files left behind", fs.readdirSync(path.dirname(cityPath)).sort().join() === "GeoLite2-ASN.mmdb,GeoLite2-City.mmdb");

  maxmind.calls.length = 0;
  const again = await updater.download();
  check("download: nothing changed upstream, so only HEAD requests and no reload", again.changed === 0 && again.detail === "Already up to date." && maxmind.calls.length === 2 && maxmind.calls.every((c) => c.startsWith("HEAD")) && reloads === 1);
  maxmind.calls.length = 0;
  maxmind.lastModified = "Fri, 02 Oct 2026 12:00:00 GMT";
  maxmind.built = 1790300000;
  clock += 8 * 86400000;
  check("due again after a week", updater.due() === true);
  const newer = await updater.download();
  check("download: newer upstream files replace the old ones", newer.changed === 2 && fs.readFileSync(cityPath, "utf8").endsWith("1790300000") && reloads === 2 && maxmind.calls.length === 4);
  const forced = await updater.download({ force: true });
  check("download: force fetches even when unchanged", forced.changed === 2);

  // --- failures ---
  updater.save({ licenseKey: "wrongkey999" });
  let err = await updater.download().then(() => null, (e) => e);
  check("download: rejected credentials are explained and recorded", err && err.status === 502 && /rejected the account ID or license key/.test(err.message) && updater.describe().lastUpdate.ok === false && fs.existsSync(cityPath));
  updater.save({ licenseKey: "goodkey123" });
  maxmind.status = 429;
  err = await updater.download({ force: true }).then(() => null, (e) => e);
  check("download: the daily limit is explained", err && /daily download limit/.test(err.message));
  maxmind.status = null;
  const down = createGeoIpUpdater({ db, geoip, validate, fetchImpl: async () => { const e = new TypeError("fetch failed"); e.cause = { code: "ENOTFOUND", hostname: "download.maxmind.com" }; throw e; }, now: () => clock, logger: { log() {}, warn() {} } });
  err = await down.download({ force: true }).then(() => null, (e) => e);
  check("download: an unreachable MaxMind says why", err && /Could not reach MaxMind: fetch failed \(ENOTFOUND download\.maxmind\.com/.test(err.message), err && err.message);
  const nokey = createGeoIpUpdater({ db: openDatabase({ file: ":memory:" }), geoip, validate, fetchImpl });
  err = await nokey.download().then(() => null, (e) => e);
  check("download: without credentials it asks for them", err && err.status === 400 && /account ID and license key first/.test(err.message));

  // --- upload ---
  const up = await updater.upload(fakeDb("GeoLite2-ASN", 1791000000));
  check("upload: the kind is read from the file and it lands in the right slot", up.installed.kind === "asn" && fs.readFileSync(asnPath, "utf8").endsWith("1791000000") && up.status.files.asn.builtAt === 1791000000);
  const upTar = await updater.upload(archive("GeoLite2-City", 1791000001));
  check("upload: MaxMind's tar.gz works too", upTar.installed.kind === "city" && fs.readFileSync(cityPath, "utf8").endsWith("1791000001"));
  err = await updater.upload(Buffer.from("this is not a database")).then(() => null, (e) => e);
  check("upload: junk is refused and the installed file is untouched", err && err.status === 400 && /not a readable MaxMind database/.test(err.message) && fs.readFileSync(cityPath, "utf8").endsWith("1791000001"));
  err = await updater.upload(fakeDb("GeoLite2-Country", 5)).then(() => null, (e) => e);
  check("upload: a database of another kind is refused with its type", err && err.status === 400 && /GeoLite2-Country/.test(err.message));

  // --- remove, forget ---
  const removed = await updater.removeFiles();
  check("remove: both files gone, readers reopened", removed.removed === 2 && !fs.existsSync(cityPath) && !fs.existsSync(asnPath) && removed.status.files.city === null);
  const cleared = updater.save({ clearCredentials: true });
  check("forget: credentials removed, updates no longer due", cleared.accountId === "" && cleared.hasLicenseKey === false && updater.due() === false && cleared.nextUpdateAt === null);

  db.close();
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(report() ? 0 : 1);
})().catch((error) => { console.error(error); process.exit(1); });
