/**
 * SQLite storage for ingested reports and the queries behind every analysis view.
 *
 * Times are unix seconds throughout. Report windows come from the report itself
 * (date_range begin/end); message times come from the mailbox (receivedDateTime).
 * A "filter" is { from, to, domain }: from/to bound the report window start, and
 * domain limits to reports about one policy_published domain.
 */
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const Database = require("better-sqlite3");
const { isLikelyForward } = require("./dmarc-parser");
const { parsePattern, compileSenders, findSender } = require("./ipmatch");

// 2: records.forwarded (likely forward / mailing list, derived from reasons and DKIM results)
// 3: mailbox_id on messages, reports and sync_runs (multi-mailbox / multi-tenant)
// 4: known_senders (created by the schema; version bump only)
// 5: alerts (created by the schema; version bump only)
// 6: ip_info country/city/ASN columns
// 7: daily_totals (retention rollups) and reports.purged_at
const SCHEMA_VERSION = 7;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS messages (
  graph_id            TEXT PRIMARY KEY,
  mailbox_id          TEXT NOT NULL DEFAULT 'env',
  internet_message_id TEXT,
  received_at         INTEGER NOT NULL,
  subject             TEXT,
  from_addr           TEXT,
  status              TEXT NOT NULL,   -- ingested | no_report | error
  error               TEXT,
  processed_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_received ON messages(received_at);

CREATE TABLE IF NOT EXISTS reports (
  id              INTEGER PRIMARY KEY,
  message_id      TEXT,            -- messages.graph_id; not a FK because the report is stored first
  mailbox_id      TEXT NOT NULL DEFAULT 'env',
  org_name        TEXT NOT NULL,
  org_email       TEXT,
  report_id       TEXT NOT NULL,
  range_begin     INTEGER NOT NULL,
  range_end       INTEGER NOT NULL,
  domain          TEXT NOT NULL,
  adkim           TEXT,
  aspf            TEXT,
  p               TEXT,
  sp              TEXT,
  pct             INTEGER,
  fo              TEXT,
  messages        INTEGER NOT NULL DEFAULT 0,
  passed          INTEGER NOT NULL DEFAULT 0,
  attachment_name TEXT,
  xml_gz          BLOB,
  ingested_at     INTEGER NOT NULL,
  purged_at       INTEGER,         -- set by retention once records and XML were rolled up and removed
  UNIQUE(org_name, report_id, domain)
);
CREATE INDEX IF NOT EXISTS idx_reports_begin  ON reports(range_begin);
CREATE INDEX IF NOT EXISTS idx_reports_domain ON reports(domain);
CREATE INDEX IF NOT EXISTS idx_reports_org    ON reports(org_name);

CREATE TABLE IF NOT EXISTS records (
  id            INTEGER PRIMARY KEY,
  report_id     INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  source_ip     TEXT NOT NULL,
  count         INTEGER NOT NULL,
  disposition   TEXT NOT NULL,
  dkim_eval     TEXT,
  spf_eval      TEXT,
  passed        INTEGER NOT NULL,
  forwarded     INTEGER NOT NULL DEFAULT 0,  -- failed, but looks like a forward / mailing list
  reasons       TEXT,            -- JSON [{type, comment}]
  envelope_to   TEXT,
  envelope_from TEXT,
  header_from   TEXT,
  dkim_results  TEXT,            -- JSON [{domain, selector, result, humanResult}]
  spf_results   TEXT,            -- JSON [{domain, scope, result}]
  dkim_domain   TEXT,
  spf_domain    TEXT
);
CREATE INDEX IF NOT EXISTS idx_records_report ON records(report_id);
CREATE INDEX IF NOT EXISTS idx_records_ip     ON records(source_ip);
CREATE INDEX IF NOT EXISTS idx_records_passed ON records(passed);

CREATE TABLE IF NOT EXISTS ip_info (
  ip           TEXT PRIMARY KEY,
  ptr          TEXT,
  looked_up_at INTEGER NOT NULL,
  country_code TEXT,
  country      TEXT,
  city         TEXT,
  asn          INTEGER,
  as_org       TEXT,
  geo_source   TEXT,               -- file | online | file+online | none
  geo_at       INTEGER
);

CREATE TABLE IF NOT EXISTS sync_runs (
  id            INTEGER PRIMARY KEY,
  mailbox_id    TEXT,
  started_at    INTEGER NOT NULL,
  finished_at   INTEGER,
  trigger       TEXT NOT NULL,
  since         INTEGER,
  messages_seen INTEGER NOT NULL DEFAULT 0,
  reports_added INTEGER NOT NULL DEFAULT 0,
  duplicates    INTEGER NOT NULL DEFAULT 0,
  errors        INTEGER NOT NULL DEFAULT 0,
  error_text    TEXT
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS known_senders (
  id         INTEGER PRIMARY KEY,
  pattern    TEXT NOT NULL UNIQUE,   -- IP, CIDR, hostname or *.suffix (lower-cased)
  kind       TEXT NOT NULL,          -- ours | vendor | other
  label      TEXT NOT NULL,
  note       TEXT,
  source     TEXT NOT NULL DEFAULT 'manual',  -- manual | spf
  created_by TEXT,
  created_at INTEGER NOT NULL
);
`;

const SENDER_KINDS = ["ours", "vendor", "other"];

const ALERTS_SCHEMA = `
CREATE TABLE IF NOT EXISTS alerts (
  id              INTEGER PRIMARY KEY,
  created_at      INTEGER NOT NULL,
  type            TEXT NOT NULL,        -- new_source | spike | new_reporter
  key             TEXT NOT NULL,        -- the IP or reporter the alert is about
  severity        TEXT NOT NULL,        -- info | medium | high
  title           TEXT NOT NULL,
  detail          TEXT,                 -- JSON
  acknowledged_at INTEGER,
  acknowledged_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_open ON alerts(acknowledged_at, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_key  ON alerts(type, key, created_at);

-- Per-day totals kept for reports whose records and XML were purged by retention.
CREATE TABLE IF NOT EXISTS daily_totals (
  day             TEXT NOT NULL,      -- YYYY-MM-DD (UTC) of the report window start
  domain          TEXT NOT NULL,
  mailbox_id      TEXT NOT NULL,
  reports         INTEGER NOT NULL DEFAULT 0,
  total           INTEGER NOT NULL DEFAULT 0,
  pass            INTEGER NOT NULL DEFAULT 0,
  fail_forward    INTEGER NOT NULL DEFAULT 0,
  fail_none       INTEGER NOT NULL DEFAULT 0,
  fail_quarantine INTEGER NOT NULL DEFAULT 0,
  fail_reject     INTEGER NOT NULL DEFAULT 0,
  fwd_quarantine  INTEGER NOT NULL DEFAULT 0,  -- likely forwards the receiver quarantined / rejected,
  fwd_reject      INTEGER NOT NULL DEFAULT 0,  -- so the Quarantined/Rejected tiles stay exact
  PRIMARY KEY (day, domain, mailbox_id)
);
`;

const DISPOSITIONS = ["none", "quarantine", "reject"];
const DAY_SECONDS = 86400;

function now() {
  return Math.floor(Date.now() / 1000);
}

function toInt(value, fallback = null) {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  const n = Number(value);
  return Number.isFinite(n) ? Math.trunc(n) : fallback;
}

function likePattern(text) {
  return `%${String(text).trim().toLowerCase().replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
}

// Record-level columns a free-text search matches against; `ptr` comes from ip_info.
const SEARCH_RECORD_COLUMNS = ["source_ip", "header_from", "envelope_from", "envelope_to", "spf_domain", "dkim_domain"];

/**
 * Builds the WHERE fragment shared by every filtered query.
 *   filter: { from, to, domain, q, excludeForwards }
 *   r: the reports table alias; x: the records alias when the query joins records,
 *      or null for report-only queries (search then looks through the report's records).
 */
function buildFilter(filter = {}, { r = "r", x = null } = {}) {
  const clauses = [];
  const params = [];
  const from = toInt(filter.from);
  const to = toInt(filter.to);
  if (from !== null) {
    clauses.push(`${r}.range_begin >= ?`);
    params.push(from);
  }
  if (to !== null) {
    clauses.push(`${r}.range_begin < ?`);
    params.push(to);
  }
  if (filter.domain) {
    clauses.push(`${r}.domain = ?`);
    params.push(String(filter.domain).toLowerCase());
  }
  if (filter.mailbox) {
    clauses.push(`${r}.mailbox_id = ?`);
    params.push(String(filter.mailbox));
  }

  const q = filter.q && String(filter.q).trim();
  if (q) {
    const like = likePattern(q);
    const reportCols = [`${r}.org_name`, `${r}.domain`, `${r}.report_id`];
    const recordMatch = (alias) => [
      ...SEARCH_RECORD_COLUMNS.map((c) => `${alias}.${c} LIKE ? ESCAPE '\\'`),
      `EXISTS (SELECT 1 FROM ip_info ip2 WHERE ip2.ip = ${alias}.source_ip AND (ip2.ptr LIKE ? ESCAPE '\\' OR ip2.as_org LIKE ? ESCAPE '\\' OR ip2.country LIKE ? ESCAPE '\\'))`
    ];
    // The ip_info clause carries three placeholders (ptr, as_org, country) for its one entry.
    if (x) {
      const parts = [...reportCols.map((c) => `${c} LIKE ? ESCAPE '\\'`), ...recordMatch(x)];
      clauses.push(`(${parts.join(" OR ")})`);
      params.push(...Array(parts.length + 2).fill(like));
    } else {
      const inner = recordMatch("x2");
      const parts = [
        ...reportCols.map((c) => `${c} LIKE ? ESCAPE '\\'`),
        `EXISTS (SELECT 1 FROM records x2 WHERE x2.report_id = ${r}.id AND (${inner.join(" OR ")}))`
      ];
      clauses.push(`(${parts.join(" OR ")})`);
      params.push(...Array(reportCols.length + inner.length + 2).fill(like));
    }
  }

  if (filter.excludeForwards && x) {
    clauses.push(`NOT (${x}.passed = 0 AND ${x}.forwarded = 1)`);
  }

  return { sql: clauses.length ? clauses.join(" AND ") : "1=1", params };
}

function splitList(value) {
  if (!value) {
    return [];
  }
  return String(value).split(",").map((s) => s.trim()).filter(Boolean);
}

function parseJson(value, fallback) {
  if (!value) {
    return fallback;
  }
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function shapeRecord(row) {
  return {
    id: row.id,
    reportId: row.report_id,
    sourceIp: row.source_ip,
    count: row.count,
    disposition: row.disposition,
    dkimEval: row.dkim_eval,
    spfEval: row.spf_eval,
    passed: Boolean(row.passed),
    likelyForward: Boolean(row.forwarded),
    reasons: parseJson(row.reasons, []),
    envelopeTo: row.envelope_to,
    envelopeFrom: row.envelope_from,
    headerFrom: row.header_from,
    dkimResults: parseJson(row.dkim_results, []),
    spfResults: parseJson(row.spf_results, []),
    dkimDomain: row.dkim_domain,
    spfDomain: row.spf_domain,
    // Present when the query joined reports.
    orgName: row.org_name,
    domain: row.domain,
    rangeBegin: row.range_begin,
    rangeEnd: row.range_end,
    policy: row.p,
    ptr: row.ptr === undefined ? undefined : row.ptr,
    countryCode: row.country_code === undefined ? undefined : row.country_code,
    asn: row.asn === undefined ? undefined : row.asn,
    asOrg: row.as_org === undefined ? undefined : row.as_org
  };
}

function shapeReport(row) {
  return {
    id: row.id,
    messageId: row.message_id,
    mailboxId: row.mailbox_id,
    orgName: row.org_name,
    orgEmail: row.org_email,
    reportId: row.report_id,
    rangeBegin: row.range_begin,
    rangeEnd: row.range_end,
    domain: row.domain,
    adkim: row.adkim,
    aspf: row.aspf,
    p: row.p,
    sp: row.sp,
    pct: row.pct,
    fo: row.fo,
    messages: row.messages,
    passed: row.passed,
    failed: row.messages - row.passed,
    attachmentName: row.attachment_name,
    ingestedAt: row.ingested_at,
    purgedAt: row.purged_at || null,
    receivedAt: row.received_at === undefined ? undefined : row.received_at,
    subject: row.subject === undefined ? undefined : row.subject
  };
}

/** Brings a database created by an earlier version up to the current schema. */
function migrate(db) {
  const version = db.pragma("user_version", { simple: true });
  if (version >= SCHEMA_VERSION) {
    return;
  }

  const columns = db.pragma("table_info(records)").map((c) => c.name);
  if (!columns.includes("forwarded")) {
    db.exec("ALTER TABLE records ADD COLUMN forwarded INTEGER NOT NULL DEFAULT 0");
  }

  // Re-derive the forward flag for every failed record already stored.
  if (version < 2) {
    const update = db.prepare("UPDATE records SET forwarded = ? WHERE id = ?");
    const rows = db.prepare("SELECT id, passed, reasons, dkim_results, header_from FROM records WHERE passed = 0").all();
    db.transaction(() => {
      for (const row of rows) {
        const flag = isLikelyForward({
          passed: false,
          reasons: parseJson(row.reasons, []),
          dkimResults: parseJson(row.dkim_results, []),
          headerFrom: row.header_from
        });
        update.run(flag ? 1 : 0, row.id);
      }
    })();
  }

  if (version < 3) {
    for (const table of ["messages", "reports", "sync_runs"]) {
      const cols = db.pragma(`table_info(${table})`).map((c) => c.name);
      if (!cols.includes("mailbox_id")) {
        const def = table === "sync_runs" ? "TEXT" : "TEXT NOT NULL DEFAULT 'env'";
        db.exec(`ALTER TABLE ${table} ADD COLUMN mailbox_id ${def}`);
      }
    }
    db.exec("UPDATE sync_runs SET mailbox_id = 'env' WHERE mailbox_id IS NULL");
    db.exec("CREATE INDEX IF NOT EXISTS idx_reports_mailbox ON reports(mailbox_id)");
  }

  if (version < 7) {
    const cols = db.pragma("table_info(reports)").map((c) => c.name);
    if (!cols.includes("purged_at")) {
      db.exec("ALTER TABLE reports ADD COLUMN purged_at INTEGER");
    }
  }

  if (version < 6) {
    const cols = db.pragma("table_info(ip_info)").map((c) => c.name);
    for (const [name, type] of [["country_code", "TEXT"], ["country", "TEXT"], ["city", "TEXT"], ["asn", "INTEGER"], ["as_org", "TEXT"], ["geo_source", "TEXT"], ["geo_at", "INTEGER"]]) {
      if (!cols.includes(name)) {
        db.exec(`ALTER TABLE ip_info ADD COLUMN ${name} ${type}`);
      }
    }
  }

  db.pragma(`user_version = ${SCHEMA_VERSION}`);
}

/**
 * Opens (or creates) the database. Pass `{ file: ":memory:" }` for tests.
 */
function openDatabase({ dataDir, file } = {}) {
  const dbPath = file || path.join(dataDir, "dmarc.sqlite");
  if (!file && dataDir) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.pragma("synchronous = NORMAL");
  db.exec(SCHEMA);
  db.exec(ALERTS_SCHEMA);
  migrate(db);

  const stmts = {
    hasMessage: db.prepare("SELECT 1 FROM messages WHERE graph_id = ?"),
    upsertMessage: db.prepare(`
      INSERT INTO messages (graph_id, mailbox_id, internet_message_id, received_at, subject, from_addr, status, error, processed_at)
      VALUES (@graphId, @mailboxId, @internetMessageId, @receivedAt, @subject, @fromAddr, @status, @error, @processedAt)
      ON CONFLICT(graph_id) DO UPDATE SET
        status = excluded.status, error = excluded.error, processed_at = excluded.processed_at`),
    insertReport: db.prepare(`
      INSERT OR IGNORE INTO reports (message_id, mailbox_id, org_name, org_email, report_id, range_begin, range_end, domain,
        adkim, aspf, p, sp, pct, fo, messages, passed, attachment_name, xml_gz, ingested_at)
      VALUES (@messageId, @mailboxId, @orgName, @orgEmail, @reportId, @rangeBegin, @rangeEnd, @domain,
        @adkim, @aspf, @p, @sp, @pct, @fo, @messages, @passed, @attachmentName, @xmlGz, @ingestedAt)`),
    insertRecord: db.prepare(`
      INSERT INTO records (report_id, source_ip, count, disposition, dkim_eval, spf_eval, passed, forwarded, reasons,
        envelope_to, envelope_from, header_from, dkim_results, spf_results, dkim_domain, spf_domain)
      VALUES (@reportId, @sourceIp, @count, @disposition, @dkimEval, @spfEval, @passed, @forwarded, @reasons,
        @envelopeTo, @envelopeFrom, @headerFrom, @dkimResults, @spfResults, @dkimDomain, @spfDomain)`),
    maxReceived: db.prepare("SELECT MAX(received_at) AS v FROM messages"),
    maxReceivedFor: db.prepare("SELECT MAX(received_at) AS v FROM messages WHERE mailbox_id = ?"),
    getSetting: db.prepare("SELECT value FROM settings WHERE key = ?"),
    setSetting: db.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"),
    startRun: db.prepare("INSERT INTO sync_runs (started_at, trigger, since, mailbox_id) VALUES (?, ?, ?, ?)"),
    lastRunsByMailbox: db.prepare(`SELECT * FROM sync_runs s WHERE s.id = (SELECT MAX(id) FROM sync_runs WHERE mailbox_id IS s.mailbox_id)`),
    mailboxCounts: db.prepare(`SELECT mailbox_id AS id, COUNT(*) AS reports, COALESCE(SUM(messages), 0) AS messages,
      MAX(range_end) AS lastWindow FROM reports GROUP BY mailbox_id`),
    finishRun: db.prepare(`UPDATE sync_runs SET finished_at = @finishedAt, messages_seen = @messagesSeen,
      reports_added = @reportsAdded, duplicates = @duplicates, errors = @errors, error_text = @errorText WHERE id = @id`),
    runs: db.prepare("SELECT * FROM sync_runs ORDER BY id DESC LIMIT ?"),
    lastRun: db.prepare("SELECT * FROM sync_runs ORDER BY id DESC LIMIT 1"),
    ipsMissingPtr: db.prepare(`SELECT DISTINCT x.source_ip AS ip FROM records x
      LEFT JOIN ip_info i ON i.ip = x.source_ip WHERE i.ip IS NULL LIMIT ?`),
    setPtr: db.prepare("INSERT INTO ip_info (ip, ptr, looked_up_at) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET ptr = excluded.ptr, looked_up_at = excluded.looked_up_at"),
    reportXml: db.prepare("SELECT xml_gz, attachment_name, org_name, report_id FROM reports WHERE id = ?"),
    reportById: db.prepare("SELECT r.*, m.received_at, m.subject FROM reports r LEFT JOIN messages m ON m.graph_id = r.message_id WHERE r.id = ?"),
    recordsForReport: db.prepare(`SELECT x.*, i.ptr FROM records x LEFT JOIN ip_info i ON i.ip = x.source_ip
      WHERE x.report_id = ? ORDER BY x.passed ASC, x.count DESC`)
  };

  const insertReportTx = db.transaction(({ messageId, mailboxId, attachmentName, parsed, xml }) => {
    const { metadata, policy, records } = parsed;
    let messages = 0;
    let passed = 0;
    for (const r of records) {
      messages += r.count;
      if (r.passed) {
        passed += r.count;
      }
    }

    const result = stmts.insertReport.run({
      messageId: messageId || null,
      mailboxId: mailboxId || "env",
      orgName: metadata.orgName || metadata.email || "unknown",
      orgEmail: metadata.email,
      reportId: metadata.reportId || `${metadata.dateRange.begin}-${metadata.dateRange.end}`,
      rangeBegin: metadata.dateRange.begin,
      rangeEnd: metadata.dateRange.end,
      domain: policy.domain,
      adkim: policy.adkim,
      aspf: policy.aspf,
      p: policy.p,
      sp: policy.sp,
      pct: policy.pct,
      fo: policy.fo,
      messages,
      passed,
      attachmentName: attachmentName || null,
      xmlGz: xml ? zlib.gzipSync(Buffer.from(xml, "utf8")) : null,
      ingestedAt: now()
    });

    if (result.changes === 0) {
      return { reportId: null, duplicate: true, messages, passed };
    }

    const reportId = Number(result.lastInsertRowid);
    for (const r of records) {
      stmts.insertRecord.run({
        reportId,
        sourceIp: r.sourceIp,
        count: r.count,
        disposition: r.disposition,
        dkimEval: r.dkimEval,
        spfEval: r.spfEval,
        passed: r.passed ? 1 : 0,
        forwarded: (r.likelyForward === undefined ? isLikelyForward(r) : r.likelyForward) ? 1 : 0,
        reasons: JSON.stringify(r.reasons || []),
        envelopeTo: r.envelopeTo,
        envelopeFrom: r.envelopeFrom,
        headerFrom: r.headerFrom,
        dkimResults: JSON.stringify(r.dkimResults || []),
        spfResults: JSON.stringify(r.spfResults || []),
        dkimDomain: r.dkimDomain,
        spfDomain: r.spfDomain
      });
    }
    return { reportId, duplicate: false, messages, passed };
  });

  // --- ingest -----------------------------------------------------------------

  function hasMessage(graphId) {
    return Boolean(stmts.hasMessage.get(graphId));
  }

  function recordMessage({ graphId, mailboxId, internetMessageId, receivedAt, subject, fromAddr, status, error }) {
    stmts.upsertMessage.run({
      graphId,
      mailboxId: mailboxId || "env",
      internetMessageId: internetMessageId || null,
      receivedAt: toInt(receivedAt, now()),
      subject: subject || null,
      fromAddr: fromAddr || null,
      status,
      error: error || null,
      processedAt: now()
    });
  }

  function insertReport(args) {
    return insertReportTx(args);
  }

  function latestMessageReceivedAt(mailboxId) {
    const row = mailboxId ? stmts.maxReceivedFor.get(mailboxId) : stmts.maxReceived.get();
    return row.v || null;
  }

  // --- analysis ---------------------------------------------------------------

  function summary(filter = {}) {
    const f = buildFilter(filter, { x: "x" });
    const fr = buildFilter(filter);

    const totals = db.prepare(`
      SELECT COALESCE(SUM(x.count), 0) AS messages,
             COALESCE(SUM(CASE WHEN x.passed THEN x.count ELSE 0 END), 0) AS passed,
             COALESCE(SUM(CASE WHEN x.passed = 0 AND x.forwarded THEN x.count ELSE 0 END), 0) AS likelyForwards,
             COALESCE(SUM(CASE WHEN x.disposition = 'quarantine' THEN x.count ELSE 0 END), 0) AS quarantined,
             COALESCE(SUM(CASE WHEN x.disposition = 'reject' THEN x.count ELSE 0 END), 0) AS rejected,
             COALESCE(SUM(CASE WHEN x.dkim_eval = 'pass' THEN x.count ELSE 0 END), 0) AS dkimPassed,
             COALESCE(SUM(CASE WHEN x.spf_eval = 'pass' THEN x.count ELSE 0 END), 0) AS spfPassed,
             COUNT(DISTINCT x.source_ip) AS sourceIps,
             COUNT(DISTINCT CASE WHEN x.passed = 0 THEN x.source_ip END) AS failingIps
      FROM records x JOIN reports r ON r.id = x.report_id
      WHERE ${f.sql}`).get(...f.params);

    const reportTotals = db.prepare(`
      SELECT COUNT(*) AS reports, COUNT(DISTINCT r.org_name) AS reporters, COUNT(DISTINCT r.domain) AS domains,
             MIN(r.range_begin) AS firstWindow, MAX(r.range_end) AS lastWindow
      FROM reports r WHERE ${fr.sql}`).get(...fr.params);

    const days = db.prepare(`
      SELECT date(r.range_begin, 'unixepoch') AS day,
             SUM(x.count) AS total,
             SUM(CASE WHEN x.passed THEN x.count ELSE 0 END) AS pass,
             SUM(CASE WHEN x.passed = 0 AND x.forwarded THEN x.count ELSE 0 END) AS failForward,
             SUM(CASE WHEN x.passed = 0 AND x.forwarded = 0 AND x.disposition = 'none' THEN x.count ELSE 0 END) AS failNone,
             SUM(CASE WHEN x.passed = 0 AND x.forwarded = 0 AND x.disposition = 'quarantine' THEN x.count ELSE 0 END) AS failQuarantine,
             SUM(CASE WHEN x.passed = 0 AND x.forwarded = 0 AND x.disposition = 'reject' THEN x.count ELSE 0 END) AS failReject
      FROM records x JOIN reports r ON r.id = x.report_id
      WHERE ${f.sql}
      GROUP BY day ORDER BY day`).all(...f.params);

    // Purged reports live on as daily totals; fold them in unless a search narrows to records.
    const rolled = filter.q ? [] : dailyTotals(filter);
    const dayMap = new Map(days.map((d) => [d.day, { ...d }]));
    for (const r of rolled) {
      const fwd = filter.excludeForwards ? 0 : r.fail_forward;
      const t = filter.excludeForwards ? r.total - r.fail_forward : r.total;
      totals.messages += t;
      totals.passed += r.pass;
      totals.likelyForwards += fwd;
      totals.quarantined += r.fail_quarantine + (filter.excludeForwards ? 0 : r.fwd_quarantine);
      totals.rejected += r.fail_reject + (filter.excludeForwards ? 0 : r.fwd_reject);
      const d = dayMap.get(r.day) || { day: r.day, total: 0, pass: 0, failForward: 0, failNone: 0, failQuarantine: 0, failReject: 0 };
      d.total += t;
      d.pass += r.pass;
      d.failForward += fwd;
      d.failNone += r.fail_none;
      d.failQuarantine += r.fail_quarantine;
      d.failReject += r.fail_reject;
      dayMap.set(r.day, d);
    }
    const mergedDays = [...dayMap.values()].sort((a, b) => (a.day < b.day ? -1 : a.day > b.day ? 1 : 0));

    const failed = totals.messages - totals.passed;
    return {
      totals: {
        ...totals,
        ...reportTotals,
        failed,
        failPct: totals.messages ? Math.round((failed / totals.messages) * 1000) / 10 : 0,
        passPct: totals.messages ? Math.round((totals.passed / totals.messages) * 1000) / 10 : 0,
        rolledUpReports: rolled.reduce((n, r) => n + r.reports, 0)
      },
      days: mergedDays.map((d) => ({ ...d, fail: d.failForward + d.failNone + d.failQuarantine + d.failReject })),
      bySender: bySender(filter),
      topReporters: reporters(filter).slice(0, 8),
      topFailingIps: ips(filter, { failingOnly: true, limit: 10 })
    };
  }

  function ips(filter = {}, { failingOnly = false, limit = 200, ip } = {}) {
    const f = buildFilter(filter, { x: "x" });
    const extra = ip ? " AND x.source_ip = ?" : "";
    const params = ip ? [...f.params, ip] : f.params;
    const rows = db.prepare(`
      SELECT x.source_ip AS ip,
             SUM(x.count) AS total,
             SUM(CASE WHEN x.passed THEN x.count ELSE 0 END) AS passedTotal,
             SUM(CASE WHEN x.passed = 0 AND x.forwarded THEN x.count ELSE 0 END) AS likelyForwards,
             SUM(CASE WHEN x.passed = 0 AND x.disposition = 'none' THEN x.count ELSE 0 END) AS failNone,
             SUM(CASE WHEN x.disposition = 'quarantine' THEN x.count ELSE 0 END) AS quarantined,
             SUM(CASE WHEN x.disposition = 'reject' THEN x.count ELSE 0 END) AS rejected,
             SUM(CASE WHEN x.dkim_eval = 'pass' THEN x.count ELSE 0 END) AS dkimPassed,
             SUM(CASE WHEN x.spf_eval = 'pass' THEN x.count ELSE 0 END) AS spfPassed,
             MIN(r.range_begin) AS firstSeen,
             MAX(r.range_end) AS lastSeen,
             COUNT(DISTINCT r.id) AS reports,
             COUNT(DISTINCT r.org_name) AS reporters,
             GROUP_CONCAT(DISTINCT r.org_name) AS reporterNames,
             GROUP_CONCAT(DISTINCT r.domain) AS domains,
             GROUP_CONCAT(DISTINCT x.header_from) AS headerFroms,
             GROUP_CONCAT(DISTINCT x.envelope_from) AS envelopeFroms,
             GROUP_CONCAT(DISTINCT x.spf_domain) AS spfDomains,
             GROUP_CONCAT(DISTINCT x.dkim_domain) AS dkimDomains,
             MAX(i.ptr) AS ptr,
             MAX(i.country_code) AS countryCode,
             MAX(i.country) AS country,
             MAX(i.city) AS city,
             MAX(i.asn) AS asn,
             MAX(i.as_org) AS asOrg
      FROM records x
      JOIN reports r ON r.id = x.report_id
      LEFT JOIN ip_info i ON i.ip = x.source_ip
      WHERE ${f.sql}${extra}
      GROUP BY x.source_ip
      ${failingOnly ? "HAVING passedTotal < total" : ""}
      ORDER BY (total - passedTotal) DESC, total DESC
      LIMIT ?`).all(...params, limit);

    return rows.map(({ passedTotal, ...row }) => ({
      ...row,
      sender: senderFor(row.ip, row.ptr),
      passed: passedTotal,
      failed: row.total - passedTotal,
      failPct: row.total ? Math.round(((row.total - passedTotal) / row.total) * 1000) / 10 : 0,
      reporterNames: splitList(row.reporterNames),
      domains: splitList(row.domains),
      headerFroms: splitList(row.headerFroms),
      envelopeFroms: splitList(row.envelopeFroms),
      spfDomains: splitList(row.spfDomains),
      dkimDomains: splitList(row.dkimDomains)
    }));
  }

  function ipDetail(ip, filter = {}) {
    const [aggregate] = ips(filter, { ip, limit: 1 });
    if (!aggregate) {
      return null;
    }
    const { rows } = records(filter, { ip, pageSize: 500 });
    return { ...aggregate, records: rows };
  }

  function records(filter = {}, { result, ip, org, page = 1, pageSize = 100 } = {}) {
    const f = buildFilter(filter, { x: "x" });
    const clauses = [f.sql];
    const params = [...f.params];
    if (result === "fail") {
      clauses.push("x.passed = 0");
    } else if (result === "pass") {
      clauses.push("x.passed = 1");
    }
    if (ip) {
      clauses.push("x.source_ip = ?");
      params.push(ip);
    }
    if (org) {
      clauses.push("r.org_name = ?");
      params.push(org);
    }
    const where = clauses.join(" AND ");
    const size = Math.min(Math.max(1, toInt(pageSize, 100)), 5000);
    const offset = (Math.max(1, toInt(page, 1)) - 1) * size;

    const total = db.prepare(`SELECT COUNT(*) AS n FROM records x JOIN reports r ON r.id = x.report_id WHERE ${where}`).get(...params).n;
    const rows = db.prepare(`
      SELECT x.*, r.org_name, r.domain, r.range_begin, r.range_end, r.p, i.ptr, i.country_code, i.as_org, i.asn
      FROM records x
      JOIN reports r ON r.id = x.report_id
      LEFT JOIN ip_info i ON i.ip = x.source_ip
      WHERE ${where}
      ORDER BY r.range_begin DESC, x.passed ASC, x.count DESC
      LIMIT ? OFFSET ?`).all(...params, size, offset);

    return { total, page: Math.max(1, toInt(page, 1)), pageSize: size, rows: rows.map(shapeRecord) };
  }

  function reports(filter = {}, { org, page = 1, pageSize = 50 } = {}) {
    const f = buildFilter(filter);
    const clauses = [f.sql];
    const params = [...f.params];
    if (org) {
      clauses.push("r.org_name = ?");
      params.push(org);
    }
    const where = clauses.join(" AND ");
    const size = Math.min(Math.max(1, toInt(pageSize, 50)), 1000);
    const offset = (Math.max(1, toInt(page, 1)) - 1) * size;

    const total = db.prepare(`SELECT COUNT(*) AS n FROM reports r WHERE ${where}`).get(...params).n;
    const rows = db.prepare(`
      SELECT r.id, r.message_id, r.mailbox_id, r.org_name, r.org_email, r.report_id, r.range_begin, r.range_end, r.domain,
             r.adkim, r.aspf, r.p, r.sp, r.pct, r.fo, r.messages, r.passed, r.attachment_name, r.ingested_at,
             m.received_at, m.subject
      FROM reports r LEFT JOIN messages m ON m.graph_id = r.message_id
      WHERE ${where}
      ORDER BY r.range_begin DESC, r.id DESC
      LIMIT ? OFFSET ?`).all(...params, size, offset);

    return { total, page: Math.max(1, toInt(page, 1)), pageSize: size, rows: rows.map(shapeReport) };
  }

  function reportById(id) {
    const row = stmts.reportById.get(id);
    if (!row) {
      return null;
    }
    const report = shapeReport(row);
    report.records = stmts.recordsForReport.all(id).map(shapeRecord);
    return report;
  }

  function reportXml(id) {
    const row = stmts.reportXml.get(id);
    if (!row || !row.xml_gz) {
      return null;
    }
    const base = (row.attachment_name || `${row.org_name}-${row.report_id}`).replace(/\.(zip|gz)$/i, "");
    return {
      fileName: /\.xml$/i.test(base) ? base : `${base}.xml`,
      xml: zlib.gunzipSync(row.xml_gz).toString("utf8")
    };
  }

  function reporters(filter = {}) {
    const f = buildFilter(filter, { x: "x" });
    return db.prepare(`
      SELECT r.org_name AS orgName, MAX(r.org_email) AS orgEmail, COUNT(DISTINCT r.id) AS reportCount,
             SUM(x.count) AS messageTotal, SUM(CASE WHEN x.passed THEN x.count ELSE 0 END) AS passedTotal,
             MAX(r.range_end) AS lastSeen, MIN(r.range_begin) AS firstSeen
      FROM records x JOIN reports r ON r.id = x.report_id
      WHERE ${f.sql}
      GROUP BY r.org_name ORDER BY messageTotal DESC, reportCount DESC`).all(...f.params)
      .map(({ reportCount, messageTotal, passedTotal, ...row }) => ({
        ...row,
        reports: reportCount,
        messages: messageTotal,
        passed: passedTotal,
        failed: messageTotal - passedTotal,
        failPct: messageTotal ? Math.round(((messageTotal - passedTotal) / messageTotal) * 1000) / 10 : 0
      }));
  }

  function domains() {
    return db.prepare(`
      SELECT r.domain AS domain, COUNT(*) AS reports, SUM(r.messages) AS messageTotal, SUM(r.passed) AS passedTotal,
             MAX(r.range_end) AS lastSeen
      FROM reports r GROUP BY r.domain ORDER BY messageTotal DESC`).all()
      .map(({ messageTotal, passedTotal, ...row }) => ({ ...row, messages: messageTotal, passed: passedTotal }));
  }

  /** Counts for the status endpoint; not filtered. */
  function stats() {
    const m = db.prepare(`SELECT COUNT(*) AS total,
        SUM(CASE WHEN status = 'ingested' THEN 1 ELSE 0 END) AS ingested,
        SUM(CASE WHEN status = 'no_report' THEN 1 ELSE 0 END) AS noReport,
        SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS errors,
        MAX(received_at) AS lastReceived FROM messages`).get();
    const r = db.prepare("SELECT COUNT(*) AS reports, COALESCE(SUM(messages), 0) AS messages, MIN(range_begin) AS firstWindow, MAX(range_end) AS lastWindow FROM reports").get();
    return { messages: m, reports: r };
  }

  function messagesWithErrors(limit = 50) {
    return db.prepare("SELECT * FROM messages WHERE status = 'error' ORDER BY received_at DESC LIMIT ?").all(limit);
  }

  // --- known senders ----------------------------------------------------------

  let compiledSenders = null;

  function knownSenders() {
    return db.prepare("SELECT * FROM known_senders ORDER BY kind, label, pattern").all();
  }

  function compiled() {
    if (!compiledSenders) {
      compiledSenders = compileSenders(knownSenders());
    }
    return compiledSenders;
  }

  function validateSender(fields, { partial = false } = {}) {
    const out = {};
    if (!partial || fields.pattern !== undefined) {
      const parsed = parsePattern(fields.pattern);
      if (!parsed) {
        const e = new Error("Pattern must be an IP address, a CIDR block (10.0.0.0/8, 2a01:111::/32), a host name or *.suffix.");
        e.status = 400;
        throw e;
      }
      out.pattern = parsed.pattern;
    }
    if (!partial || fields.kind !== undefined) {
      const kind = String(fields.kind || "").toLowerCase();
      if (!SENDER_KINDS.includes(kind)) {
        const e = new Error(`Kind must be one of ${SENDER_KINDS.join(", ")}.`);
        e.status = 400;
        throw e;
      }
      out.kind = kind;
    }
    if (!partial || fields.label !== undefined) {
      const label = String(fields.label || "").trim();
      if (!label || label.length > 80) {
        const e = new Error("Label is required (80 characters maximum).");
        e.status = 400;
        throw e;
      }
      out.label = label;
    }
    if (fields.note !== undefined) {
      out.note = String(fields.note || "").trim().slice(0, 500) || null;
    }
    return out;
  }

  function addKnownSender(fields, { createdBy = null, source = "manual" } = {}) {
    const v = validateSender(fields);
    try {
      const result = db.prepare(`INSERT INTO known_senders (pattern, kind, label, note, source, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`).run(v.pattern, v.kind, v.label, v.note || null, source === "spf" ? "spf" : "manual", createdBy, now());
      compiledSenders = null;
      return db.prepare("SELECT * FROM known_senders WHERE id = ?").get(Number(result.lastInsertRowid));
    } catch (error) {
      if (/UNIQUE/.test(error.message)) {
        const e = new Error(`${v.pattern} is already a known sender.`);
        e.status = 409;
        throw e;
      }
      throw error;
    }
  }

  function updateKnownSender(id, fields) {
    const current = db.prepare("SELECT * FROM known_senders WHERE id = ?").get(id);
    if (!current) {
      const e = new Error("No such known sender.");
      e.status = 404;
      throw e;
    }
    const v = validateSender(fields, { partial: true });
    const next = { ...current, ...v };
    try {
      db.prepare("UPDATE known_senders SET pattern = ?, kind = ?, label = ?, note = ? WHERE id = ?").run(next.pattern, next.kind, next.label, next.note || null, id);
    } catch (error) {
      if (/UNIQUE/.test(error.message)) {
        const e = new Error(`${next.pattern} is already a known sender.`);
        e.status = 409;
        throw e;
      }
      throw error;
    }
    compiledSenders = null;
    return db.prepare("SELECT * FROM known_senders WHERE id = ?").get(id);
  }

  function removeKnownSender(id) {
    const result = db.prepare("DELETE FROM known_senders WHERE id = ?").run(id);
    compiledSenders = null;
    if (!result.changes) {
      const e = new Error("No such known sender.");
      e.status = 404;
      throw e;
    }
    return true;
  }

  /** The known sender an IP (and its reverse-DNS name) belongs to, or null. */
  function senderFor(ip, ptr) {
    const row = findSender(compiled(), ip, ptr);
    return row ? { id: row.id, kind: row.kind, label: row.label, pattern: row.pattern } : null;
  }

  /** Totals per sender kind for the filtered period: ours, vendor, other, unknown. */
  function bySender(filter = {}) {
    const out = {};
    for (const kind of [...SENDER_KINDS, "unknown"]) {
      out[kind] = { sources: 0, total: 0, passed: 0, failed: 0, likelyForwards: 0 };
    }
    for (const row of ips(filter, { limit: 5000 })) {
      const kind = row.sender ? row.sender.kind : "unknown";
      out[kind].sources += 1;
      out[kind].total += row.total;
      out[kind].passed += row.passed;
      out[kind].failed += row.failed;
      out[kind].likelyForwards += row.likelyForwards || 0;
    }
    return out;
  }

  // --- weekly summary -------------------------------------------------------------

  /** Sources whose very first report window (across all stored data for the domain/mailbox) starts inside [from, to). */
  function firstSeenSources({ from, to, domain, mailbox } = {}) {
    const f = buildFilter({ domain, mailbox }, { x: "x" });
    return db.prepare(`
      SELECT x.source_ip AS ip,
             MIN(r.range_begin) AS firstSeen,
             SUM(x.count) AS total,
             SUM(CASE WHEN x.passed = 0 THEN x.count ELSE 0 END) AS failed,
             MAX(i.ptr) AS ptr,
             MAX(i.as_org) AS asOrg,
             MAX(i.country_code) AS countryCode
      FROM records x
      JOIN reports r ON r.id = x.report_id
      LEFT JOIN ip_info i ON i.ip = x.source_ip
      WHERE ${f.sql}
      GROUP BY x.source_ip
      HAVING firstSeen >= ? AND firstSeen < ?
      ORDER BY failed DESC, total DESC`).all(...f.params, toInt(from, 0), toInt(to, 0))
      .map((row) => ({ ...row, sender: senderFor(row.ip, row.ptr) }));
  }

  // --- retention: rollups and purge ----------------------------------------------

  /** Daily totals of purged reports inside the filter's window, domain and mailbox. */
  function dailyTotals(filter = {}) {
    const clauses = [];
    const params = [];
    const from = toInt(filter.from);
    const to = toInt(filter.to);
    if (from !== null) {
      clauses.push("day >= date(?, 'unixepoch')");
      params.push(from);
    }
    if (to !== null) {
      clauses.push("day < date(?, 'unixepoch')");
      params.push(to);
    }
    if (filter.domain) {
      clauses.push("domain = ?");
      params.push(String(filter.domain).toLowerCase());
    }
    if (filter.mailbox) {
      clauses.push("mailbox_id = ?");
      params.push(String(filter.mailbox));
    }
    return db.prepare(`SELECT day, domain, mailbox_id, SUM(reports) AS reports, SUM(total) AS total, SUM(pass) AS pass,
        SUM(fail_forward) AS fail_forward, SUM(fail_none) AS fail_none, SUM(fail_quarantine) AS fail_quarantine, SUM(fail_reject) AS fail_reject,
        SUM(fwd_quarantine) AS fwd_quarantine, SUM(fwd_reject) AS fwd_reject
      FROM daily_totals ${clauses.length ? "WHERE " + clauses.join(" AND ") : ""} GROUP BY day, domain, mailbox_id ORDER BY day`).all(...params);
  }

  /**
   * Rolls the records of reports whose window started before `cutoff` (unix seconds)
   * into daily_totals, then deletes those records and the stored XML. The report rows
   * stay (marked purged) so counts, reporters and the report list still make sense.
   */
  const purgeBeforeTx = db.transaction((cutoff) => {
    const victims = db.prepare("SELECT id, domain, mailbox_id, range_begin FROM reports WHERE range_begin < ? AND purged_at IS NULL").all(cutoff);
    if (!victims.length) {
      return { reports: 0, records: 0, days: 0 };
    }
    const upsert = db.prepare(`INSERT INTO daily_totals (day, domain, mailbox_id, reports, total, pass, fail_forward, fail_none, fail_quarantine, fail_reject, fwd_quarantine, fwd_reject)
      VALUES (@day, @domain, @mailboxId, @reports, @total, @pass, @failForward, @failNone, @failQuarantine, @failReject, @fwdQuarantine, @fwdReject)
      ON CONFLICT(day, domain, mailbox_id) DO UPDATE SET
        reports = reports + excluded.reports, total = total + excluded.total, pass = pass + excluded.pass,
        fail_forward = fail_forward + excluded.fail_forward, fail_none = fail_none + excluded.fail_none,
        fail_quarantine = fail_quarantine + excluded.fail_quarantine, fail_reject = fail_reject + excluded.fail_reject,
        fwd_quarantine = fwd_quarantine + excluded.fwd_quarantine, fwd_reject = fwd_reject + excluded.fwd_reject`);
    const sums = db.prepare(`SELECT COALESCE(SUM(count), 0) AS total,
        COALESCE(SUM(CASE WHEN passed THEN count ELSE 0 END), 0) AS pass,
        COALESCE(SUM(CASE WHEN passed = 0 AND forwarded THEN count ELSE 0 END), 0) AS failForward,
        COALESCE(SUM(CASE WHEN passed = 0 AND forwarded = 0 AND disposition = 'none' THEN count ELSE 0 END), 0) AS failNone,
        COALESCE(SUM(CASE WHEN passed = 0 AND forwarded = 0 AND disposition = 'quarantine' THEN count ELSE 0 END), 0) AS failQuarantine,
        COALESCE(SUM(CASE WHEN passed = 0 AND forwarded = 0 AND disposition = 'reject' THEN count ELSE 0 END), 0) AS failReject,
        COALESCE(SUM(CASE WHEN passed = 0 AND forwarded = 1 AND disposition = 'quarantine' THEN count ELSE 0 END), 0) AS fwdQuarantine,
        COALESCE(SUM(CASE WHEN passed = 0 AND forwarded = 1 AND disposition = 'reject' THEN count ELSE 0 END), 0) AS fwdReject
      FROM records WHERE report_id = ?`);
    const delRecords = db.prepare("DELETE FROM records WHERE report_id = ?");
    const markReport = db.prepare("UPDATE reports SET xml_gz = NULL, purged_at = ? WHERE id = ?");
    const at = now();
    const daysTouched = new Set();
    let records = 0;
    for (const v of victims) {
      const s = sums.get(v.id);
      const day = new Date(v.range_begin * 1000).toISOString().slice(0, 10);
      upsert.run({ day, domain: v.domain, mailboxId: v.mailbox_id || "env", reports: 1, ...s });
      records += delRecords.run(v.id).changes;
      markReport.run(at, v.id);
      daysTouched.add(`${day}|${v.domain}|${v.mailbox_id}`);
    }
    return { reports: victims.length, records, days: daysTouched.size };
  });

  function purgeBefore(cutoff) {
    return purgeBeforeTx(toInt(cutoff, 0));
  }

  function retentionInfo() {
    const r = db.prepare(`SELECT COUNT(*) AS purgedReports, MIN(CASE WHEN purged_at IS NULL THEN range_begin END) AS earliestRetained,
        MAX(purged_at) AS lastPurgeAt FROM reports`).get();
    const t = db.prepare("SELECT COUNT(*) AS days, COALESCE(SUM(total), 0) AS messages FROM daily_totals").get();
    return { purgedReports: db.prepare("SELECT COUNT(*) AS n FROM reports WHERE purged_at IS NOT NULL").get().n, earliestRetained: r.earliestRetained, lastPurgeAt: r.lastPurgeAt, rolledUpDays: t.days, rolledUpMessages: t.messages };
  }

  // --- policy readiness ---------------------------------------------------------

  /** DKIM selectors seen in reports for a domain (from auth_results), with pass/fail message counts. */
  function dkimSelectors(domain, filter = {}) {
    const f = buildFilter({ ...filter, domain }, { x: "x" });
    return db.prepare(`
      SELECT json_extract(d.value, '$.domain') AS signingDomain,
             json_extract(d.value, '$.selector') AS selector,
             SUM(CASE WHEN json_extract(d.value, '$.result') = 'pass' THEN x.count ELSE 0 END) AS passedTotal,
             SUM(CASE WHEN json_extract(d.value, '$.result') <> 'pass' THEN x.count ELSE 0 END) AS failedTotal,
             COUNT(DISTINCT x.source_ip) AS sources,
             MAX(r.range_end) AS lastSeen
      FROM records x
      JOIN reports r ON r.id = x.report_id
      JOIN json_each(x.dkim_results) d
      WHERE ${f.sql} AND json_extract(d.value, '$.selector') IS NOT NULL
      GROUP BY signingDomain, selector
      ORDER BY passedTotal + failedTotal DESC`).all(...f.params)
      .map(({ passedTotal, failedTotal, ...row }) => ({ ...row, passed: passedTotal, failed: failedTotal }));
  }

  // --- alerts -------------------------------------------------------------------

  function shapeAlert(row) {
    return { ...row, detail: parseJson(row.detail, {}) };
  }

  function insertAlert({ type, key, severity = "medium", title, detail = {}, createdAt }) {
    const result = db.prepare("INSERT INTO alerts (created_at, type, key, severity, title, detail) VALUES (?, ?, ?, ?, ?, ?)")
      .run(toInt(createdAt, now()), type, String(key), severity, title, JSON.stringify(detail));
    return shapeAlert(db.prepare("SELECT * FROM alerts WHERE id = ?").get(Number(result.lastInsertRowid)));
  }

  function openAlerts(limit = 100) {
    return db.prepare("SELECT * FROM alerts WHERE acknowledged_at IS NULL ORDER BY created_at DESC, id DESC LIMIT ?").all(limit).map(shapeAlert);
  }

  function recentAlerts(limit = 50) {
    return db.prepare("SELECT * FROM alerts ORDER BY created_at DESC, id DESC LIMIT ?").all(limit).map(shapeAlert);
  }

  function openAlertCount() {
    return db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE acknowledged_at IS NULL").get().n;
  }

  /** Whether an alert of this type exists for the key: open ones by default, or any since a time. */
  function alertExists(type, key, { openOnly = true, since = null } = {}) {
    const clauses = ["type = ?", "key = ?"];
    const params = [type, String(key)];
    if (openOnly) clauses.push("acknowledged_at IS NULL");
    if (since !== null) {
      clauses.push("created_at >= ?");
      params.push(since);
    }
    return Boolean(db.prepare(`SELECT 1 FROM alerts WHERE ${clauses.join(" AND ")} LIMIT 1`).get(...params));
  }

  function ackAlert(id, user = null) {
    return db.prepare("UPDATE alerts SET acknowledged_at = ?, acknowledged_by = ? WHERE id = ? AND acknowledged_at IS NULL").run(now(), user, id).changes > 0;
  }

  function ackAllAlerts(user = null) {
    return db.prepare("UPDATE alerts SET acknowledged_at = ?, acknowledged_by = ? WHERE acknowledged_at IS NULL").run(now(), user).changes;
  }

  /** Failing IPs whose only records are in the given (just added) reports. */
  function newFailingSources(reportIds) {
    const json = JSON.stringify(reportIds);
    return db.prepare(`
      SELECT x.source_ip AS ip,
             SUM(x.count) AS total,
             SUM(CASE WHEN x.passed = 0 THEN x.count ELSE 0 END) AS failed,
             MIN(r.range_begin) AS firstSeen,
             GROUP_CONCAT(DISTINCT r.org_name) AS reporters,
             GROUP_CONCAT(DISTINCT x.header_from) AS headerFroms,
             MAX(i.ptr) AS ptr
      FROM records x
      JOIN reports r ON r.id = x.report_id
      LEFT JOIN ip_info i ON i.ip = x.source_ip
      WHERE x.report_id IN (SELECT value FROM json_each(?))
        AND NOT EXISTS (SELECT 1 FROM records y WHERE y.source_ip = x.source_ip AND y.report_id NOT IN (SELECT value FROM json_each(?)))
      GROUP BY x.source_ip
      HAVING failed > 0
      ORDER BY failed DESC`).all(json, json)
      .map((row) => ({ ...row, reporters: splitList(row.reporters), headerFroms: splitList(row.headerFroms) }));
  }

  /** Reporting organisations whose only reports are the given (just added) ones. */
  function newReporters(reportIds) {
    const json = JSON.stringify(reportIds);
    return db.prepare(`
      SELECT r.org_name AS orgName, COUNT(*) AS reports, SUM(r.messages) AS messages
      FROM reports r
      WHERE r.id IN (SELECT value FROM json_each(?))
        AND NOT EXISTS (SELECT 1 FROM reports o WHERE o.org_name = r.org_name AND o.id NOT IN (SELECT value FROM json_each(?)))
      GROUP BY r.org_name`).all(json, json);
  }

  /** IPs whose non-forward failures in the last `days` days are at least `factor` times the previous window. */
  function spikeCandidates({ now: at = now(), days = 7, minFailed = 20, factor = 3 } = {}) {
    const recentFrom = at - days * DAY_SECONDS;
    const previousFrom = recentFrom - days * DAY_SECONDS;
    return db.prepare(`
      SELECT x.source_ip AS ip,
             SUM(CASE WHEN r.range_begin >= ? THEN x.count ELSE 0 END) AS recent,
             SUM(CASE WHEN r.range_begin < ? THEN x.count ELSE 0 END) AS previous,
             MAX(i.ptr) AS ptr
      FROM records x
      JOIN reports r ON r.id = x.report_id
      LEFT JOIN ip_info i ON i.ip = x.source_ip
      WHERE x.passed = 0 AND x.forwarded = 0 AND r.range_begin >= ?
      GROUP BY x.source_ip
      HAVING recent >= ? AND recent >= ? * MAX(previous, 1)
      ORDER BY recent DESC`).all(recentFrom, recentFrom, previousFrom, minFailed, factor);
  }

  // --- ip_info ----------------------------------------------------------------

  function ipsMissingPtr(limit = 200) {
    return stmts.ipsMissingPtr.all(limit).map((r) => r.ip);
  }

  function setPtr(ip, ptr) {
    stmts.setPtr.run(ip, ptr || null, now());
  }

  /** Source IPs with no geo lookup yet (ip_info row missing or never geo-resolved). */
  function ipsMissingGeo(limit = 500) {
    return db.prepare(`SELECT DISTINCT x.source_ip AS ip FROM records x
      LEFT JOIN ip_info i ON i.ip = x.source_ip WHERE i.geo_at IS NULL LIMIT ?`).all(limit).map((r) => r.ip);
  }

  function setGeo(ip, info = {}) {
    db.prepare(`INSERT INTO ip_info (ip, ptr, looked_up_at, country_code, country, city, asn, as_org, geo_source, geo_at)
      VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(ip) DO UPDATE SET country_code = excluded.country_code, country = excluded.country, city = excluded.city,
        asn = excluded.asn, as_org = excluded.as_org, geo_source = excluded.geo_source, geo_at = excluded.geo_at`)
      .run(ip, now(), info.countryCode || null, info.country || null, info.city || null, info.asn || null, info.asOrg || null, info.source || "none", now());
  }

  /** Forgets every geo answer so the next lookup pass redoes them (after adding the MaxMind files, say). */
  function clearGeo() {
    return db.prepare("UPDATE ip_info SET country_code = NULL, country = NULL, city = NULL, asn = NULL, as_org = NULL, geo_source = NULL, geo_at = NULL").run().changes;
  }

  function geoStats() {
    return db.prepare(`SELECT COUNT(*) AS resolved, SUM(CASE WHEN geo_source = 'none' THEN 1 ELSE 0 END) AS unknown,
      SUM(CASE WHEN geo_source LIKE 'file%' THEN 1 ELSE 0 END) AS fromFiles, SUM(CASE WHEN geo_source = 'online' THEN 1 ELSE 0 END) AS fromOnline
      FROM ip_info WHERE geo_at IS NOT NULL`).get();
  }

  // --- sync runs / settings ---------------------------------------------------

  function startRun(trigger, since, mailboxId = "env") {
    return Number(stmts.startRun.run(now(), trigger, since || null, mailboxId).lastInsertRowid);
  }

  /** The most recent run of every mailbox, for the mailbox table. */
  function lastRunsByMailbox() {
    return stmts.lastRunsByMailbox.all();
  }

  /** Reports and messages stored per mailbox, for the filter dropdown. */
  function mailboxCounts() {
    return stmts.mailboxCounts.all();
  }

  function finishRun(id, { messagesSeen = 0, reportsAdded = 0, duplicates = 0, errors = 0, errorText = null }) {
    stmts.finishRun.run({ id, finishedAt: now(), messagesSeen, reportsAdded, duplicates, errors, errorText });
  }

  function runs(limit = 20) {
    return stmts.runs.all(limit);
  }

  function lastRun() {
    return stmts.lastRun.get() || null;
  }

  function getSetting(key) {
    const row = stmts.getSetting.get(key);
    return row ? row.value : null;
  }

  function setSetting(key, value) {
    stmts.setSetting.run(key, value === null || value === undefined ? null : String(value));
  }

  function close() {
    db.close();
  }

  return {
    db,
    hasMessage,
    recordMessage,
    insertReport,
    latestMessageReceivedAt,
    summary,
    ips,
    ipDetail,
    records,
    reports,
    reportById,
    reportXml,
    reporters,
    domains,
    stats,
    messagesWithErrors,
    ipsMissingPtr,
    setPtr,
    ipsMissingGeo,
    setGeo,
    clearGeo,
    geoStats,
    startRun,
    finishRun,
    runs,
    lastRun,
    lastRunsByMailbox,
    mailboxCounts,
    knownSenders,
    addKnownSender,
    updateKnownSender,
    removeKnownSender,
    senderFor,
    bySender,
    dkimSelectors,
    firstSeenSources,
    dailyTotals,
    purgeBefore,
    retentionInfo,
    insertAlert,
    openAlerts,
    recentAlerts,
    openAlertCount,
    alertExists,
    ackAlert,
    ackAllAlerts,
    newFailingSources,
    newReporters,
    spikeCandidates,
    getSetting,
    setSetting,
    close
  };
}

module.exports = { openDatabase, buildFilter, DISPOSITIONS };
