/**
 * One-time analyses: a user uploads reports and looks at them with the full
 * dashboard, but nothing is written to the main database. Each analysis is an
 * in-memory SQLite database with the same schema, fed through the same ingest
 * path, and served by the same analysis routes (server.js mounts them under
 * /api/scratch/:id with req.db pointing here). Known-sender labels and the
 * reverse-DNS / GeoIP answers already in the main store are copied in so the
 * sources table reads the same; new IPs are resolved on the spot. An analysis
 * belongs to the user who started it and is dropped after an hour of silence.
 */
const crypto = require("crypto");

const DEFAULT_TTL_MS = 60 * 60 * 1000;
const SWEEP_EVERY_MS = 5 * 60 * 1000;
const LOOKUP_WAIT_MS = 10 * 1000;

function createScratchStore({ openDatabase, createIngest, createSync, mainDb, geoip = null, ttlMs = DEFAULT_TTL_MS, max = 20, now = Date.now, logger = console } = {}) {
  const analyses = new Map();
  let timer = null;

  function create(username) {
    sweep();
    if (analyses.size >= max) {
      // Drop the least recently used one rather than refuse.
      const oldest = [...analyses.values()].sort((a, b) => a.lastUsed - b.lastUsed)[0];
      remove(oldest.id);
    }
    const db = openDatabase({ file: ":memory:" });
    for (const s of mainDb ? mainDb.knownSenders() : []) {
      try {
        db.addKnownSender({ pattern: s.pattern, kind: s.kind, label: s.label, note: s.note }, { source: s.source, createdBy: s.created_by });
      } catch (error) {
        logger.warn?.(`scratch: could not copy known sender ${s.pattern}: ${error.message}`);
      }
    }
    const scratch = {
      id: crypto.randomBytes(12).toString("hex"),
      username: username || null,
      createdAt: now(),
      lastUsed: now(),
      db,
      ingest: createIngest({ db }),
      sync: createSync ? createSync({ db, geoip, logger: { warn() {}, error() {}, log() {} } }) : null,
      files: [],
      seq: 0
    };
    analyses.set(scratch.id, scratch);
    return scratch;
  }

  /** The analysis, if it exists and belongs to this user; touching it keeps it alive. */
  function get(id, username) {
    const scratch = analyses.get(String(id || ""));
    if (!scratch) return null;
    if (scratch.username !== (username || null)) return null;
    if (now() - scratch.lastUsed > ttlMs) {
      remove(scratch.id);
      return null;
    }
    scratch.lastUsed = now();
    return scratch;
  }

  function remove(id) {
    const scratch = analyses.get(id);
    if (!scratch) return false;
    analyses.delete(id);
    try {
      scratch.db.close();
    } catch { /* already closed */ }
    return true;
  }

  /** Ingests one file, then fills in PTR/geo for its IPs: from the main store first, then live (briefly). */
  async function addFile(scratch, { bytes, name = "" }) {
    scratch.seq += 1;
    const messageId = `scratch:${scratch.seq}`;
    const result = scratch.ingest.ingestFile({ bytes, name, messageId, mailboxId: "upload" });
    scratch.db.recordMessage({
      graphId: messageId,
      mailboxId: "upload",
      receivedAt: Math.floor(now() / 1000),
      subject: name || "uploaded file",
      fromAddr: scratch.username,
      status: result.found ? "ingested" : result.problems.length ? "error" : "no_report",
      error: result.problems.length ? result.problems.join("; ").slice(0, 2000) : null
    });
    scratch.files.push({ name, size: bytes.length, at: Math.floor(now() / 1000), aggregate: result.aggregate.added, tls: result.tls.added, forensic: result.forensic.added, duplicates: result.aggregate.duplicates + result.tls.duplicates + result.forensic.duplicates, problems: result.problems });

    if (result.aggregate.added && mainDb) {
      const missing = scratch.db.ipsMissingPtr(5000);
      if (missing.length) scratch.db.importIpInfo(mainDb.ipInfoRows(missing));
    }
    if (result.aggregate.added && scratch.sync) {
      // Resolve what the main store did not know, but do not keep the upload waiting forever.
      const lookups = scratch.sync.lookupPtrs().then(() => scratch.sync.lookupGeo()).catch((error) => logger.warn?.(`scratch: lookups failed: ${error.message}`));
      await Promise.race([lookups, new Promise((resolve) => setTimeout(resolve, LOOKUP_WAIT_MS).unref?.())]);
    }
    scratch.lastUsed = now();
    return result;
  }

  function describe(scratch) {
    const stats = scratch.db.stats();
    return {
      id: scratch.id,
      createdAt: Math.floor(scratch.createdAt / 1000),
      expiresAt: Math.floor((scratch.lastUsed + ttlMs) / 1000),
      files: scratch.files,
      reports: stats.reports ? stats.reports.reports : 0,
      messages: stats.reports ? stats.reports.messages : 0,
      tls: scratch.db.tlsCount(),
      forensic: scratch.db.forensicCount(),
      domains: scratch.db.domains().map((d) => d.domain)
    };
  }

  function sweep() {
    for (const scratch of [...analyses.values()]) {
      if (now() - scratch.lastUsed > ttlMs) remove(scratch.id);
    }
  }

  function start() {
    if (timer) return;
    timer = setInterval(sweep, SWEEP_EVERY_MS);
    if (typeof timer.unref === "function") timer.unref();
  }

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
    for (const id of [...analyses.keys()]) remove(id);
  }

  return { create, get, remove, addFile, describe, sweep, start, stop, size: () => analyses.size };
}

module.exports = { createScratchStore, DEFAULT_TTL_MS };
