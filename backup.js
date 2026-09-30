/**
 * Backup and restore of everything the analyzer keeps in its data directory:
 * the SQLite database (a consistent online-backup copy), users.json and
 * mailboxes.json. The archive is a plain gzip-compressed tar, written and read
 * here with the few dozen lines that needs, so `tar -xzf` can open it too.
 *
 * Sessions are not included (they are short-lived and would sign people in on
 * a restored copy), nor are GeoLite2 files (large and re-downloadable).
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const { upgradeFile } = require("./db");

const FORMAT = "dmarc-report-analyzer-backup";
const FORMAT_VERSION = 1;
const DB_NAME = "dmarc.sqlite";
const SETTINGS_FILES = ["users.json", "mailboxes.json"];

// --- tar ----------------------------------------------------------------------

function octal(value, length) {
  return value.toString(8).padStart(length - 1, "0") + "\0";
}

function tarHeader(name, size, mtime) {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, "utf8");
  h.write(octal(0o644, 8), 100);
  h.write(octal(0, 8), 108);
  h.write(octal(0, 8), 116);
  h.write(octal(size, 12), 124);
  h.write(octal(Math.floor(mtime / 1000), 12), 136);
  h.fill(0x20, 148, 156); // checksum field counts as spaces while summing
  h.write("0", 156); // regular file
  h.write("ustar\0", 257);
  h.write("00", 263);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  return h;
}

/** Packs { name: Buffer } entries into a tar buffer. */
function tarPack(entries, mtime = Date.now()) {
  const parts = [];
  for (const [name, data] of Object.entries(entries)) {
    parts.push(tarHeader(name, data.length, mtime), data);
    const pad = (512 - (data.length % 512)) % 512;
    if (pad) parts.push(Buffer.alloc(pad));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

/** Reads a tar buffer into { name: Buffer }; only regular files are kept. */
function tarUnpack(buffer) {
  const out = {};
  let offset = 0;
  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break;
    const name = header.toString("utf8", 0, 100).replace(/\0.*$/, "");
    const size = parseInt(header.toString("utf8", 124, 136).replace(/\0.*$/, "").trim() || "0", 8);
    const type = header.toString("utf8", 156, 157);
    offset += 512;
    if (type === "0" || type === "\0") {
      out[name] = Buffer.from(buffer.subarray(offset, offset + size));
    }
    offset += size + ((512 - (size % 512)) % 512);
  }
  return out;
}

// --- backup -------------------------------------------------------------------

/** Writes a .tar.gz of the database and settings to `dest`; returns the manifest. */
async function createBackup({ db, dataDir, dest, now = Date.now, version = "" }) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-backup-"));
  const snapshot = path.join(tmpDir, DB_NAME);
  try {
    await db.snapshot(snapshot);
    const entries = {};
    const manifest = { format: FORMAT, formatVersion: FORMAT_VERSION, createdAt: new Date(now()).toISOString(), app: version, files: [] };
    entries[DB_NAME] = fs.readFileSync(snapshot);
    manifest.files.push(DB_NAME);
    for (const name of SETTINGS_FILES) {
      const file = path.join(dataDir, name);
      if (fs.existsSync(file)) {
        entries[name] = fs.readFileSync(file);
        manifest.files.push(name);
      }
    }
    entries["manifest.json"] = Buffer.from(JSON.stringify(manifest, null, 2), "utf8");
    const tar = tarPack(entries, now());
    fs.writeFileSync(dest, zlib.gzipSync(tar, { level: 6 }));
    manifest.bytes = fs.statSync(dest).size;
    return manifest;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

/** Inspects an uploaded archive without changing anything. */
function inspectBackup(buffer) {
  let tar;
  try {
    tar = zlib.gunzipSync(buffer);
  } catch (error) {
    throw fail(400, "That is not a gzip file. A backup is the .tar.gz downloaded from this page.");
  }
  const entries = tarUnpack(tar);
  if (!entries["manifest.json"] || !entries[DB_NAME]) {
    throw fail(400, "The archive is missing manifest.json or the database, so it is not a backup made by this app.");
  }
  let manifest;
  try {
    manifest = JSON.parse(entries["manifest.json"].toString("utf8"));
  } catch {
    throw fail(400, "The backup's manifest is not readable.");
  }
  if (manifest.format !== FORMAT) {
    throw fail(400, `The manifest says "${manifest.format}", not a DMARC analyzer backup.`);
  }
  if (Number(manifest.formatVersion) > FORMAT_VERSION) {
    throw fail(400, `The backup was made by a newer version (format ${manifest.formatVersion}); update the app first.`);
  }
  return { manifest, entries };
}

/**
 * Restores an archive: the database is upgraded to the current schema and copied
 * in table by table; users.json and mailboxes.json are overwritten when present.
 * Returns what was restored.
 */
function restoreBackup({ db, dataDir, buffer }) {
  const { manifest, entries } = inspectBackup(buffer);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-restore-"));
  try {
    // Check everything before touching anything, so a bad archive changes nothing.
    for (const name of SETTINGS_FILES) {
      if (!entries[name]) continue;
      try {
        JSON.parse(entries[name].toString("utf8"));
      } catch {
        throw fail(400, `${name} in the backup is not valid JSON; nothing was changed.`);
      }
    }
    const dbFile = path.join(tmpDir, DB_NAME);
    fs.writeFileSync(dbFile, entries[DB_NAME]);
    const info = upgradeFile(dbFile);
    const counts = db.importFrom(dbFile);
    const settings = [];
    for (const name of SETTINGS_FILES) {
      if (!entries[name]) continue;
      fs.writeFileSync(path.join(dataDir, name), entries[name]);
      try {
        fs.chmodSync(path.join(dataDir, name), 0o600);
      } catch {
        // chmod is a no-op on some Windows setups; not fatal.
      }
      settings.push(name);
    }
    return { manifest, database: info, counts, settings };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function fail(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

module.exports = { createBackup, inspectBackup, restoreBackup, tarPack, tarUnpack, FORMAT, FORMAT_VERSION, DB_NAME };
