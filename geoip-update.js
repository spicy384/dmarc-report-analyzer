/**
 * Getting the MaxMind GeoLite2 files onto the host from the Settings page instead
 * of copying them by hand: download them with a MaxMind account ID and license
 * key (and keep them fresh once a week), or upload a file. Each file is checked
 * to be a readable MaxMind database of the right kind before it replaces the one
 * in use, and the readers are reopened afterwards.
 *
 * The license key is kept in the settings table and never sent back to the browser.
 */
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const { tarUnpack } = require("./backup");
const { describeFetchError } = require("./net-errors");

const KEY = "geoip";
const EDITIONS = { city: "GeoLite2-City", asn: "GeoLite2-ASN" };
const DOWNLOAD_BASE = "https://download.maxmind.com/geoip/databases";
const UPDATE_EVERY_MS = 7 * 24 * 60 * 60 * 1000;
const CHECK_EVERY_MS = 6 * 60 * 60 * 1000;
const MAX_DB_BYTES = 400 * 1024 * 1024;

function fail(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

/** Reads a database's metadata with the maxmind reader; throws when the bytes are not one. */
function defaultValidate(buffer) {
  const { Reader } = require("maxmind");
  const reader = new Reader(buffer);
  const meta = reader.metadata || {};
  const built = meta.buildEpoch ? Math.floor(new Date(meta.buildEpoch).getTime() / 1000) : null;
  return { databaseType: String(meta.databaseType || ""), builtAt: Number.isFinite(built) ? built : null };
}

/** Which slot a database belongs in, from its type: "city", "asn" or null. */
function kindOf(databaseType) {
  if (/city/i.test(databaseType)) return "city";
  if (/asn|isp/i.test(databaseType)) return "asn";
  return null;
}

/** The .mmdb inside whatever was handed over: a bare file, a .gz, or MaxMind's .tar.gz. */
function extractDatabase(bytes) {
  let buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    buf = zlib.gunzipSync(buf, { maxOutputLength: MAX_DB_BYTES });
  }
  // A tar archive has "ustar" at offset 257 of its first header.
  if (buf.length > 512 && buf.toString("latin1", 257, 262) === "ustar") {
    const entries = tarUnpack(buf);
    const name = Object.keys(entries).find((n) => /\.mmdb$/i.test(n));
    if (!name) throw fail(400, "The archive does not contain a .mmdb file.");
    return entries[name];
  }
  return buf;
}

function createGeoIpUpdater({ db, geoip, fetchImpl = globalThis.fetch, validate = defaultValidate, now = Date.now, logger = console, onUpdated = null, onlineDefault = true, downloadBase = DOWNLOAD_BASE } = {}) {
  let timer = null;
  let running = null;

  function stored() {
    try {
      return JSON.parse(db.getSetting(KEY) || "{}") || {};
    } catch {
      return {};
    }
  }

  function remember(patch) {
    db.setSetting(KEY, JSON.stringify({ ...stored(), ...patch }));
  }

  /** Whether ip-api.com may be asked: the Settings choice when one was made, else the environment default. */
  function onlineEnabled() {
    const s = stored();
    return typeof s.online === "boolean" ? s.online : Boolean(onlineDefault);
  }

  /** What the browser may see: everything except the license key itself. */
  function describe() {
    const s = stored();
    const g = geoip.describe();
    return {
      accountId: s.accountId || "",
      hasLicenseKey: Boolean(s.licenseKey),
      autoUpdate: s.autoUpdate !== false,
      online: onlineEnabled(),
      onlineSource: typeof s.online === "boolean" ? "setting" : "environment",
      onlineProvider: g.onlineProvider || "ip-api.com",
      lastUpdate: s.lastUpdate || null,
      nextUpdateAt: s.accountId && s.licenseKey && s.autoUpdate !== false ? Math.floor(((s.lastUpdate && s.lastUpdate.ok ? s.lastUpdate.at * 1000 : now()) + (s.lastUpdate && s.lastUpdate.ok ? UPDATE_EVERY_MS : 0)) / 1000) : null,
      files: { city: g.cityFile || null, asn: g.asnFile || null },
      paths: { city: g.cityPath, asn: g.asnPath },
      problems: g.problems || [],
      running: Boolean(running)
    };
  }

  function save(patch = {}) {
    const next = {};
    if (patch.accountId !== undefined) {
      const id = String(patch.accountId || "").trim();
      if (id && !/^\d{1,12}$/.test(id)) throw fail(400, "The MaxMind account ID is a number (shown on the license key page).");
      next.accountId = id;
    }
    if (patch.licenseKey !== undefined) {
      const key = String(patch.licenseKey || "").trim();
      if (key && (key.length < 8 || key.length > 80 || /\s/.test(key))) throw fail(400, "That does not look like a MaxMind license key.");
      // An empty value keeps the stored key; removing it is done with clearCredentials.
      if (key) next.licenseKey = key;
    }
    if (patch.clearCredentials === true) {
      next.accountId = "";
      next.licenseKey = "";
    }
    if (patch.autoUpdate !== undefined) next.autoUpdate = Boolean(patch.autoUpdate);
    if (patch.online !== undefined) next.online = Boolean(patch.online);
    remember(next);
    return describe();
  }

  /** Validates a database, writes it into its slot (atomically) and returns what it was. */
  function install(bytes, { expect = null } = {}) {
    const buffer = extractDatabase(bytes);
    let meta;
    try {
      meta = validate(buffer);
    } catch (error) {
      throw fail(400, `That is not a readable MaxMind database: ${error.message}`);
    }
    const kind = kindOf(meta.databaseType);
    if (!kind) throw fail(400, `This is a "${meta.databaseType || "unknown"}" database; a City and an ASN database are what the analyzer uses.`);
    if (expect && kind !== expect) throw fail(400, `Expected a ${EDITIONS[expect]} database but received "${meta.databaseType}".`);
    const g = geoip.describe();
    const target = kind === "city" ? g.cityPath : g.asnPath;
    if (!target) throw fail(500, "No location is configured for the GeoIP files.");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    const tmp = `${target}.tmp-${process.pid}`;
    try {
      fs.writeFileSync(tmp, buffer);
      fs.renameSync(tmp, target);
    } catch (error) {
      fs.rmSync(tmp, { force: true });
      throw fail(500, `Could not write ${target}: ${error.message}. If the file is mounted read-only, replace it on the host instead.`);
    }
    return { kind, databaseType: meta.databaseType, builtAt: meta.builtAt, bytes: buffer.length, path: target };
  }

  /** A file uploaded from the browser: .mmdb, .mmdb.gz or MaxMind's .tar.gz. */
  async function upload(bytes) {
    const installed = install(bytes);
    await geoip.reload();
    if (onUpdated) onUpdated([installed]);
    return { installed, status: describe() };
  }

  async function fetchEdition(kind, { accountId, licenseKey, force, previous }) {
    const edition = EDITIONS[kind];
    const url = `${downloadBase}/${edition}/download?suffix=tar.gz`;
    const headers = { Authorization: `Basic ${Buffer.from(`${accountId}:${licenseKey}`).toString("base64")}` };
    const explain = (status) => (status === 401 ? "MaxMind rejected the account ID or license key." : status === 403 ? "This MaxMind account may not download GeoLite2; accept the GeoLite2 licence in the account portal." : status === 429 ? "MaxMind's daily download limit for this account is used up; try again tomorrow." : `MaxMind answered HTTP ${status}.`);
    let lastModified = null;
    try {
      // A HEAD request does not count against the daily download limit and tells us whether anything changed.
      const head = await fetchImpl(url, { method: "HEAD", headers });
      if (!head.ok) throw fail(502, explain(head.status));
      lastModified = head.headers.get("last-modified") || null;
      const have = kind === "city" ? geoip.describe().cityFile : geoip.describe().asnFile;
      if (!force && have && lastModified && previous && previous.lastModified === lastModified) {
        return { kind, edition, skipped: true, lastModified };
      }
      const res = await fetchImpl(url, { headers });
      if (!res.ok) throw fail(502, explain(res.status));
      const bytes = Buffer.from(await res.arrayBuffer());
      const installed = install(bytes, { expect: kind });
      return { ...installed, edition, skipped: false, lastModified: res.headers.get("last-modified") || lastModified };
    } catch (error) {
      if (error.status) throw error;
      throw fail(502, `Could not reach MaxMind: ${describeFetchError(error)}`);
    }
  }

  /** Downloads both editions (or only what changed), reopens the readers, records the outcome. Never overlaps. */
  function download({ force = false } = {}) {
    if (running) return running;
    const p = (async () => {
      const s = stored();
      if (!s.accountId || !s.licenseKey) throw fail(400, "Enter the MaxMind account ID and license key first.");
      const editions = { ...((s.lastUpdate && s.lastUpdate.editions) || {}) };
      const results = [];
      try {
        for (const kind of ["city", "asn"]) {
          const r = await fetchEdition(kind, { accountId: s.accountId, licenseKey: s.licenseKey, force, previous: editions[kind] });
          results.push(r);
          editions[kind] = { lastModified: r.lastModified || null, builtAt: r.skipped ? (editions[kind] || {}).builtAt || null : r.builtAt };
        }
      } catch (error) {
        remember({ lastUpdate: { at: Math.floor(now() / 1000), ok: false, detail: error.message, editions } });
        if (results.some((r) => !r.skipped)) await geoip.reload();
        throw error;
      }
      const changed = results.filter((r) => !r.skipped);
      if (changed.length) await geoip.reload();
      const detail = changed.length ? `Downloaded ${changed.map((r) => r.edition).join(" and ")}.` : "Already up to date.";
      remember({ lastUpdate: { at: Math.floor(now() / 1000), ok: true, detail, editions } });
      if (changed.length && onUpdated) onUpdated(changed);
      return { results, changed: changed.length, detail, status: describe() };
    })().finally(() => {
      if (running === p) running = null;
    });
    running = p;
    return p;
  }

  /** Deletes the database files, going back to the online lookup (or none). */
  async function removeFiles() {
    const g = geoip.describe();
    const removed = [];
    for (const file of [g.cityPath, g.asnPath]) {
      if (file && fs.existsSync(file)) {
        try {
          fs.rmSync(file);
          removed.push(file);
        } catch (error) {
          throw fail(500, `Could not remove ${file}: ${error.message}`);
        }
      }
    }
    await geoip.reload();
    const s = stored();
    if (s.lastUpdate) remember({ lastUpdate: { ...s.lastUpdate, editions: {} } });
    return { removed: removed.length, status: describe() };
  }

  function due() {
    const s = stored();
    if (!s.accountId || !s.licenseKey || s.autoUpdate === false) return false;
    return !s.lastUpdate || now() - s.lastUpdate.at * 1000 >= (s.lastUpdate.ok ? UPDATE_EVERY_MS : 24 * 60 * 60 * 1000);
  }

  function start() {
    if (timer) return;
    const tick = () => {
      if (!due()) return;
      download().then((r) => logger.log?.(`geoip: ${r.detail}`)).catch((error) => logger.warn?.(`geoip: update failed: ${error.message}`));
    };
    const first = setTimeout(tick, 2 * 60 * 1000);
    first.unref?.();
    timer = setInterval(tick, CHECK_EVERY_MS);
    timer.unref?.();
  }

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  return { describe, save, upload, download, removeFiles, onlineEnabled, due, start, stop };
}

module.exports = { createGeoIpUpdater, extractDatabase, kindOf, EDITIONS };
