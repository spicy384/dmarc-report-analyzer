/**
 * The flat JSON files the app keeps beside the database (accounts, sessions,
 * mailboxes). Reads are cached by the file's mtime and size so a request that
 * consults them several times costs one stat each; writes go to a temporary
 * file and are renamed into place, so a crash mid-write never leaves a truncated
 * file. A file that exists but cannot be read or parsed is an error, not "empty":
 * an unreadable accounts file must block sign-in rather than reopen first-run setup.
 */
const fs = require("fs");
const path = require("path");

const cache = new Map(); // file -> { mtimeMs, size, value }

function fail(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

/** Parsed contents of `file`, or `fallback` when it does not exist. Returns a fresh copy each time. */
function readJsonFile(file, fallback) {
  let stat;
  try {
    stat = fs.statSync(file);
  } catch (error) {
    if (error.code === "ENOENT") return fallback;
    throw fail(503, `Could not read ${path.basename(file)}: ${error.message}`);
  }
  const hit = cache.get(file);
  if (hit && hit.mtimeMs === stat.mtimeMs && hit.size === stat.size) {
    return structuredClone(hit.value);
  }
  let value;
  try {
    value = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    throw fail(503, `${path.basename(file)} is unreadable or not valid JSON: ${error.message}. Fix or restore the file; the application will not start over.`);
  }
  if (value === null || value === undefined) value = fallback;
  cache.set(file, { mtimeMs: stat.mtimeMs, size: stat.size, value });
  return structuredClone(value);
}

/** Writes `value` atomically with mode 600 (these files hold hashes, secrets and tokens). */
function writeJsonFile(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), { encoding: "utf8", mode: 0o600 });
  try {
    fs.renameSync(tmp, file);
  } catch (error) {
    fs.rmSync(tmp, { force: true });
    throw error;
  }
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    // chmod is a no-op on some Windows setups; not fatal.
  }
  const stat = fs.statSync(file);
  cache.set(file, { mtimeMs: stat.mtimeMs, size: stat.size, value: structuredClone(value) });
}

function forget(file) {
  cache.delete(file);
}

module.exports = { readJsonFile, writeJsonFile, forget };
