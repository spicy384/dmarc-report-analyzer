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
const { isLikelyForward, parseAggregateReport } = require("./dmarc-parser");
const { parsePattern, compileSenders, findSender } = require("./ipmatch");
const { matchCatalogue } = require("./sender-catalogue");
const { sourceVerdict } = require("./verdict");

// 2: records.forwarded (likely forward / mailing list, derived from reasons and DKIM results)
// 3: mailbox_id on messages, reports and sync_runs (multi-mailbox / multi-tenant)
// 4: known_senders (created by the schema; version bump only)
// 5: alerts (created by the schema; version bump only)
// 6: ip_info country/city/ASN columns
// 7: daily_totals (retention rollups) and reports.purged_at
// 8: forensic_reports (created by the schema; version bump only)
const SCHEMA_VERSION = 11;

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
  type            TEXT NOT NULL,        -- new_source | spike | new_reporter | dns_change | reporter_silent | ingest_stalled
  key             TEXT NOT NULL,        -- the IP, reporter or record the alert is about
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

-- Forensic (ruf) reports: one per failing message, with the original message's headers.
CREATE TABLE IF NOT EXISTS forensic_reports (
  id                     INTEGER PRIMARY KEY,
  message_id             TEXT,                -- messages.graph_id of the report email
  mailbox_id             TEXT NOT NULL DEFAULT 'env',
  arrival_at             INTEGER,             -- when the receiver got the failing message
  source_ip              TEXT,
  reported_domain        TEXT,
  auth_failure           TEXT,                -- dmarc | dkim | spf | ...
  feedback_type          TEXT,
  delivery_result        TEXT,
  reporting_mta          TEXT,
  reporter_from          TEXT,
  original_mail_from     TEXT,
  original_rcpt_to       TEXT,
  original_from          TEXT,
  original_to            TEXT,
  original_subject       TEXT,
  original_date          INTEGER,
  original_message_id    TEXT,
  authentication_results TEXT,
  headers                TEXT,
  ingested_at            INTEGER NOT NULL,
  UNIQUE(message_id)
);
CREATE INDEX IF NOT EXISTS idx_forensic_arrival ON forensic_reports(arrival_at);
CREATE INDEX IF NOT EXISTS idx_forensic_ip      ON forensic_reports(source_ip);

-- Who changed what: mailboxes, labels, users, credentials, backups.
CREATE TABLE IF NOT EXISTS audit_log (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  at       INTEGER NOT NULL,
  username TEXT,
  action   TEXT NOT NULL,      -- e.g. mailbox.add, sender.remove, user.role, auth.login
  target   TEXT,               -- the thing acted on: a mailbox address, a pattern, a username
  detail   TEXT,               -- free text, no secrets
  ip       TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);

-- What each domain's DMARC, SPF and DKIM records looked like over time: one row per
-- distinct value with the window it was observed in. Written by the daily snapshot.
CREATE TABLE IF NOT EXISTS dns_history (
  id         INTEGER PRIMARY KEY,
  domain     TEXT NOT NULL,
  kind       TEXT NOT NULL,              -- dmarc | spf | dkim
  selector   TEXT NOT NULL DEFAULT '',   -- DKIM only
  found      INTEGER NOT NULL,           -- 0 when the record did not resolve
  value      TEXT,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dns_history_key ON dns_history(domain, kind, selector, last_seen);

-- SMTP TLS reports (RFC 8460): one row per policy in a report (reports almost always
-- carry one). Failures are kept as JSON; the raw report is gzipped for download.
CREATE TABLE IF NOT EXISTS tls_reports (
  id              INTEGER PRIMARY KEY,
  message_id      TEXT,
  mailbox_id      TEXT NOT NULL DEFAULT 'env',
  org_name        TEXT NOT NULL,
  report_id       TEXT NOT NULL,
  contact_info    TEXT,
  range_begin     INTEGER NOT NULL,
  range_end       INTEGER NOT NULL,
  policy_domain   TEXT,
  policy_type     TEXT,                -- sts | tlsa | no-policy-found
  policy_mode     TEXT,                -- enforce | testing | none, from the policy string
  policy_string   TEXT,                -- JSON [lines]
  mx_hosts        TEXT,                -- JSON [patterns]
  successful      INTEGER NOT NULL DEFAULT 0,
  failed          INTEGER NOT NULL DEFAULT 0,
  failures        TEXT,                -- JSON [{resultType, sendingMtaIp, receivingMxHostname, ...}]
  attachment_name TEXT,
  raw_gz          BLOB,
  ingested_at     INTEGER NOT NULL,
  UNIQUE(org_name, report_id, policy_domain)
);
CREATE INDEX IF NOT EXISTS idx_tls_begin  ON tls_reports(range_begin);
CREATE INDEX IF NOT EXISTS idx_tls_domain ON tls_reports(policy_domain);
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
    // Every kind of report counts towards a mailbox, so one that only ever received TLS
    // or forensic reports (or the "upload" pseudo-mailbox) still shows in the filter.
    mailboxCounts: db.prepare(`SELECT id, SUM(reports) AS reports, SUM(messages) AS messages, MAX(lastWindow) AS lastWindow FROM (
        SELECT mailbox_id AS id, COUNT(*) AS reports, COALESCE(SUM(messages), 0) AS messages, MAX(range_end) AS lastWindow FROM reports GROUP BY mailbox_id
        UNION ALL SELECT mailbox_id, COUNT(*), 0, MAX(range_end) FROM tls_reports GROUP BY mailbox_id
        UNION ALL SELECT mailbox_id, COUNT(*), 0, MAX(arrival_at) FROM forensic_reports GROUP BY mailbox_id
      ) GROUP BY id`),
    finishRun: db.prepare(`UPDATE sync_runs SET finished_at = @finishedAt, messages_seen = @messagesSeen,
      reports_added = @reportsAdded, duplicates = @duplicates, errors = @errors, error_text = @errorText WHERE id = @id`),
    runs: db.prepare("SELECT * FROM sync_runs ORDER BY id DESC LIMIT ?"),
    lastRun: db.prepare("SELECT * FROM sync_runs ORDER BY id DESC LIMIT 1"),
    ipsMissingPtr: db.prepare(`SELECT DISTINCT x.source_ip AS ip FROM records x
      LEFT JOIN ip_info i ON i.ip = x.source_ip WHERE i.ip IS NULL LIMIT ?`),
    setPtr: db.prepare("INSERT INTO ip_info (ip, ptr, looked_up_at) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET ptr = excluded.ptr, looked_up_at = excluded.looked_up_at"),
    reportXml: db.prepare("SELECT xml_gz, attachment_name, org_name, report_id FROM reports WHERE id = ?"),
    reportById: db.prepare("SELECT r.*, m.received_at, m.subject FROM reports r LEFT JOIN messages m ON m.graph_id = r.message_id WHERE r.id = ?"),
    // Joins the report so each record carries its window, domain and policy: the
    // Exchange Online block under a record needs the window.
    recordsForReport: db.prepare(`SELECT x.*, r.org_name, r.domain, r.range_begin, r.range_end, r.p, i.ptr
      FROM records x JOIN reports r ON r.id = x.report_id LEFT JOIN ip_info i ON i.ip = x.source_ip
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
             -- Raw authentication results, alignment aside: an SPF pass for the sending
             -- service's own domain, a DKIM signature by another domain, or no signature.
             SUM(CASE WHEN EXISTS (SELECT 1 FROM json_each(COALESCE(x.spf_results, '[]')) j WHERE json_extract(j.value, '$.result') = 'pass') THEN x.count ELSE 0 END) AS spfRawPass,
             SUM(CASE WHEN EXISTS (SELECT 1 FROM json_each(COALESCE(x.dkim_results, '[]')) j WHERE json_extract(j.value, '$.result') = 'pass') THEN x.count ELSE 0 END) AS dkimRawPass,
             SUM(CASE WHEN json_array_length(COALESCE(x.dkim_results, '[]')) > 0 THEN x.count ELSE 0 END) AS dkimSigned,
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

    return rows.map(({ passedTotal, ...row }) => {
      const shaped = {
        ...row,
        sender: senderFor(row.ip, row.ptr),
        // A hint about who operates the address, for unlabelled sources and the verdict.
        catalogue: matchCatalogue(row.ip, row.ptr),
        passed: passedTotal,
        failed: row.total - passedTotal,
        failPct: row.total ? Math.round(((row.total - passedTotal) / row.total) * 1000) / 10 : 0,
        reporterNames: splitList(row.reporterNames),
        domains: splitList(row.domains),
        headerFroms: splitList(row.headerFroms),
        envelopeFroms: splitList(row.envelopeFroms),
        spfDomains: splitList(row.spfDomains),
        dkimDomains: splitList(row.dkimDomains)
      };
      shaped.verdict = sourceVerdict(shaped);
      return shaped;
    });
  }

  /**
   * Per-day totals for a set of sources inside the filter, for sparklines:
   * Map(ip -> [{ day, total, failed }]). One query for all of them.
   */
  function ipDays(filter = {}, ipList = []) {
    const out = new Map();
    if (!ipList.length) return out;
    const f = buildFilter(filter, { x: "x" });
    const marks = ipList.map(() => "?").join(", ");
    const rows = db.prepare(`
      SELECT x.source_ip AS ip, date(r.range_begin, 'unixepoch') AS day,
             SUM(x.count) AS total,
             SUM(CASE WHEN x.passed THEN 0 ELSE x.count END) AS failed
      FROM records x JOIN reports r ON r.id = x.report_id
      WHERE ${f.sql} AND x.source_ip IN (${marks})
      GROUP BY ip, day ORDER BY ip, day`).all(...f.params, ...ipList);
    for (const row of rows) {
      if (!out.has(row.ip)) out.set(row.ip, []);
      out.get(row.ip).push({ day: row.day, total: row.total, failed: row.failed });
    }
    return out;
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

  /**
   * Mail grouped by the domain actually in the From header, against the domain
   * the report was for. Subdomains that only ever fail are the ones nobody
   * legitimately sends from: exactly what sp=reject exists to shut.
   */
  function subdomains(filter = {}) {
    const f = buildFilter(filter, { x: "x" });
    const rows = db.prepare(`
      SELECT COALESCE(x.header_from, '') AS domain, r.domain AS policyDomain,
             SUM(x.count) AS total,
             SUM(CASE WHEN x.passed THEN x.count ELSE 0 END) AS passedTotal,
             SUM(CASE WHEN x.passed = 0 AND x.forwarded THEN x.count ELSE 0 END) AS likelyForwards,
             SUM(CASE WHEN x.disposition = 'quarantine' THEN x.count ELSE 0 END) AS quarantined,
             SUM(CASE WHEN x.disposition = 'reject' THEN x.count ELSE 0 END) AS rejected,
             COUNT(DISTINCT x.source_ip) AS sources,
             COUNT(DISTINCT CASE WHEN x.passed = 0 THEN x.source_ip END) AS failingSources,
             COUNT(DISTINCT r.org_name) AS reporters,
             MIN(r.range_begin) AS firstSeen,
             MAX(r.range_end) AS lastSeen
      FROM records x JOIN reports r ON r.id = x.report_id
      WHERE ${f.sql}
      GROUP BY COALESCE(x.header_from, ''), r.domain
      ORDER BY total DESC`).all(...f.params);

    // The policy each report domain published most recently, for the "covered by" note.
    const policies = new Map(db.prepare(`
      SELECT domain, p, sp FROM reports WHERE id IN (SELECT MAX(id) FROM reports GROUP BY domain)`).all().map((r) => [r.domain, r]));

    return rows.map(({ passedTotal, ...row }) => {
      const domain = row.domain.toLowerCase();
      const parent = row.policyDomain.toLowerCase();
      const relation = domain === parent ? "parent" : domain.endsWith(`.${parent}`) ? "subdomain" : "other";
      const policy = policies.get(row.policyDomain) || {};
      const failed = row.total - passedTotal;
      return {
        ...row,
        relation,
        passed: passedTotal,
        failed,
        failPct: row.total ? Math.round((failed / row.total) * 1000) / 10 : 0,
        // What a receiver applies to this From domain: sp= for subdomains when set, else p=.
        appliedPolicy: relation === "subdomain" ? (policy.sp || policy.p || null) : (policy.p || null),
        inheritsPolicy: relation === "subdomain" && !policy.sp,
        unused: relation === "subdomain" && passedTotal === 0
      };
    });
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

  /**
   * One row per report domain for the period: policy, volumes, pass rate, failing
   * sources without a label, failure-only subdomains, reporters, last report, and
   * a status that says which domain needs attention first.
   */
  function scorecard(filter = {}, { now: at = now() } = {}) {
    const f = buildFilter(filter, { x: "x" });
    const rows = db.prepare(`
      SELECT r.domain AS domain,
             SUM(x.count) AS total,
             SUM(CASE WHEN x.passed THEN x.count ELSE 0 END) AS passedTotal,
             SUM(CASE WHEN x.passed = 0 AND x.forwarded THEN x.count ELSE 0 END) AS likelyForwards,
             SUM(CASE WHEN x.dkim_eval = 'pass' THEN x.count ELSE 0 END) AS dkimPassed,
             SUM(CASE WHEN x.spf_eval = 'pass' THEN x.count ELSE 0 END) AS spfPassed,
             COUNT(DISTINCT x.source_ip) AS sources,
             COUNT(DISTINCT CASE WHEN x.passed = 0 AND x.forwarded = 0 THEN x.source_ip END) AS failingSources,
             COUNT(DISTINCT r.org_name) AS reporters,
             COUNT(DISTINCT r.id) AS reports,
             MIN(r.range_begin) AS firstSeen,
             MAX(r.range_end) AS lastSeen
      FROM records x JOIN reports r ON r.id = x.report_id
      WHERE ${f.sql}
      GROUP BY r.domain ORDER BY total DESC`).all(...f.params);
    const policies = new Map(db.prepare("SELECT domain, p, sp, pct, adkim, aspf FROM reports WHERE id IN (SELECT MAX(id) FROM reports GROUP BY domain)").all().map((r) => [r.domain, r]));
    const latestAny = new Map(db.prepare("SELECT domain, MAX(range_end) AS lastSeen FROM reports GROUP BY domain").all().map((r) => [r.domain, r.lastSeen]));
    const unusedByDomain = new Map();
    for (const s of subdomains(filter)) {
      if (s.unused) unusedByDomain.set(s.policyDomain, (unusedByDomain.get(s.policyDomain) || 0) + 1);
    }
    const unlabelledByDomain = new Map();
    for (const ip of ips(filter, { failingOnly: true, limit: 5000 })) {
      if (ip.sender || ip.failed - (ip.likelyForwards || 0) <= 0) continue;
      for (const d of ip.domains) unlabelledByDomain.set(d, (unlabelledByDomain.get(d) || 0) + 1);
    }
    return rows.map(({ passedTotal, ...row }) => {
      const policy = policies.get(row.domain) || {};
      const failed = row.total - passedTotal;
      const realFailed = failed - row.likelyForwards;
      const failPct = row.total ? Math.round((realFailed / row.total) * 1000) / 10 : 0;
      const lastSeen = latestAny.get(row.domain) || row.lastSeen;
      const silentDays = lastSeen ? Math.floor((at - lastSeen) / DAY_SECONDS) : null;
      const unlabelled = unlabelledByDomain.get(row.domain) || 0;
      const unusedSubdomains = unusedByDomain.get(row.domain) || 0;
      const p = policy.p || null;
      const issues = [];
      let status = "ok";
      if (!p || p === "none") { status = "critical"; issues.push(p === "none" ? "p=none: nothing is enforced" : "no policy seen in reports"); }
      if (unlabelled > 0) { status = status === "critical" ? status : "warn"; issues.push(`${unlabelled} failing source${unlabelled === 1 ? "" : "s"} without a label`); }
      if (unusedSubdomains > 0 && (policy.sp || p) !== "reject") { status = status === "critical" ? status : "warn"; issues.push(`${unusedSubdomains} spoofed subdomain${unusedSubdomains === 1 ? "" : "s"} not at reject`); }
      if (p === "quarantine" && status === "ok") { status = "warn"; issues.push("at quarantine, not yet reject"); }
      if (policy.pct !== undefined && policy.pct !== null && policy.pct < 100) { status = status === "critical" ? status : "warn"; issues.push(`pct=${policy.pct}: only part of failing mail gets the policy`); }
      if (silentDays !== null && silentDays > 7) { status = status === "critical" ? status : "warn"; issues.push(`no report for ${silentDays} days`); }
      if (!issues.length) issues.push(realFailed ? `${failPct}% of mail still fails` : "all mail passes");
      return {
        ...row,
        passed: passedTotal,
        failed,
        realFailed,
        failPct,
        passPct: row.total ? Math.round((passedTotal / row.total) * 1000) / 10 : 0,
        spfPct: row.total ? Math.round((row.spfPassed / row.total) * 1000) / 10 : 0,
        dkimPct: row.total ? Math.round((row.dkimPassed / row.total) * 1000) / 10 : 0,
        policy: { p, sp: policy.sp || null, pct: policy.pct === undefined ? null : policy.pct, adkim: policy.adkim || null, aspf: policy.aspf || null },
        unlabelledFailingSources: unlabelled,
        unusedSubdomains,
        lastSeen,
        silentDays,
        status,
        issues
      };
    });
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

  // --- forensic reports -----------------------------------------------------------

  function shapeForensic(row) {
    return {
      id: row.id,
      messageId: row.message_id,
      mailboxId: row.mailbox_id,
      arrivalAt: row.arrival_at,
      sourceIp: row.source_ip,
      reportedDomain: row.reported_domain,
      authFailure: row.auth_failure,
      feedbackType: row.feedback_type,
      deliveryResult: row.delivery_result,
      reportingMta: row.reporting_mta,
      reporterFrom: row.reporter_from,
      originalMailFrom: row.original_mail_from,
      originalRcptTo: row.original_rcpt_to,
      originalFrom: row.original_from,
      originalTo: row.original_to,
      originalSubject: row.original_subject,
      originalDate: row.original_date,
      originalMessageId: row.original_message_id,
      authenticationResults: row.authentication_results,
      headers: row.headers === undefined ? undefined : row.headers,
      ingestedAt: row.ingested_at,
      ptr: row.ptr === undefined ? undefined : row.ptr,
      countryCode: row.country_code === undefined ? undefined : row.country_code,
      asOrg: row.as_org === undefined ? undefined : row.as_org
    };
  }

  function insertForensic({ messageId, mailboxId, parsed }) {
    const result = db.prepare(`INSERT OR IGNORE INTO forensic_reports (message_id, mailbox_id, arrival_at, source_ip, reported_domain, auth_failure,
        feedback_type, delivery_result, reporting_mta, reporter_from, original_mail_from, original_rcpt_to, original_from, original_to,
        original_subject, original_date, original_message_id, authentication_results, headers, ingested_at)
      VALUES (@messageId, @mailboxId, @arrivalAt, @sourceIp, @reportedDomain, @authFailure, @feedbackType, @deliveryResult, @reportingMta,
        @reporterFrom, @originalMailFrom, @originalRcptTo, @originalFrom, @originalTo, @originalSubject, @originalDate, @originalMessageId,
        @authenticationResults, @headers, @ingestedAt)`).run({
      messageId: messageId || null,
      mailboxId: mailboxId || "env",
      arrivalAt: parsed.arrivalAt || null,
      sourceIp: parsed.sourceIp || null,
      reportedDomain: parsed.reportedDomain || null,
      authFailure: parsed.authFailure || null,
      feedbackType: parsed.feedbackType || null,
      deliveryResult: parsed.deliveryResult || null,
      reportingMta: parsed.reportingMta || null,
      reporterFrom: parsed.reporterFrom || null,
      originalMailFrom: parsed.originalMailFrom || null,
      originalRcptTo: parsed.originalRcptTo || null,
      originalFrom: parsed.originalFrom || null,
      originalTo: parsed.originalTo || null,
      originalSubject: parsed.originalSubject || null,
      originalDate: parsed.originalDate || null,
      originalMessageId: parsed.originalMessageId || null,
      authenticationResults: parsed.authenticationResults || null,
      headers: parsed.headers || null,
      ingestedAt: now()
    });
    return { id: result.changes ? Number(result.lastInsertRowid) : null, duplicate: result.changes === 0 };
  }

  function forensicFilter(filter = {}, { ip } = {}) {
    const clauses = [];
    const params = [];
    const from = toInt(filter.from);
    const to = toInt(filter.to);
    if (from !== null) { clauses.push("f.arrival_at >= ?"); params.push(from); }
    if (to !== null) { clauses.push("f.arrival_at < ?"); params.push(to); }
    if (filter.domain) { clauses.push("f.reported_domain = ?"); params.push(String(filter.domain).toLowerCase()); }
    if (filter.mailbox) { clauses.push("f.mailbox_id = ?"); params.push(String(filter.mailbox)); }
    if (ip) { clauses.push("f.source_ip = ?"); params.push(ip); }
    const q = filter.q && String(filter.q).trim();
    if (q) {
      const like = likePattern(q);
      const cols = ["f.source_ip", "f.reported_domain", "f.auth_failure", "f.original_from", "f.original_to", "f.original_subject", "f.original_mail_from", "f.reporter_from", "f.original_message_id", "i.ptr", "i.as_org"];
      clauses.push(`(${cols.map((c) => `${c} LIKE ? ESCAPE '\\'`).join(" OR ")})`);
      params.push(...Array(cols.length).fill(like));
    }
    return { sql: clauses.length ? clauses.join(" AND ") : "1=1", params };
  }

  function forensics(filter = {}, { ip, page = 1, pageSize = 50 } = {}) {
    const f = forensicFilter(filter, { ip });
    const size = Math.min(Math.max(1, toInt(pageSize, 50)), 1000);
    const offset = (Math.max(1, toInt(page, 1)) - 1) * size;
    const total = db.prepare(`SELECT COUNT(*) AS n FROM forensic_reports f LEFT JOIN ip_info i ON i.ip = f.source_ip WHERE ${f.sql}`).get(...f.params).n;
    const rows = db.prepare(`SELECT f.id, f.message_id, f.mailbox_id, f.arrival_at, f.source_ip, f.reported_domain, f.auth_failure, f.feedback_type,
        f.delivery_result, f.reporting_mta, f.reporter_from, f.original_mail_from, f.original_rcpt_to, f.original_from, f.original_to,
        f.original_subject, f.original_date, f.original_message_id, f.authentication_results, f.ingested_at, i.ptr, i.country_code, i.as_org
      FROM forensic_reports f LEFT JOIN ip_info i ON i.ip = f.source_ip
      WHERE ${f.sql} ORDER BY f.arrival_at DESC, f.id DESC LIMIT ? OFFSET ?`).all(...f.params, size, offset);
    return { total, page: Math.max(1, toInt(page, 1)), pageSize: size, rows: rows.map(shapeForensic) };
  }

  function forensicById(id) {
    const row = db.prepare("SELECT f.*, i.ptr, i.country_code, i.as_org FROM forensic_reports f LEFT JOIN ip_info i ON i.ip = f.source_ip WHERE f.id = ?").get(id);
    return row ? shapeForensic(row) : null;
  }

  function forensicCount() {
    return db.prepare("SELECT COUNT(*) AS n FROM forensic_reports").get().n;
  }

  // --- TLS reports (RFC 8460) --------------------------------------------------

  function policyMode(lines) {
    for (const line of lines || []) {
      const m = String(line).match(/^\s*mode\s*:\s*(\w+)/i);
      if (m) return m[1].toLowerCase();
    }
    return null;
  }

  /** Stores every policy of a parsed TLS report; duplicates (same reporter, id and domain) are skipped. */
  function insertTlsReport({ messageId, mailboxId, attachmentName, parsed, json }) {
    const rawGz = json ? zlib.gzipSync(Buffer.from(json, "utf8")) : null;
    const stmt = db.prepare(`INSERT OR IGNORE INTO tls_reports (message_id, mailbox_id, org_name, report_id, contact_info, range_begin, range_end,
        policy_domain, policy_type, policy_mode, policy_string, mx_hosts, successful, failed, failures, attachment_name, raw_gz, ingested_at)
      VALUES (@messageId, @mailboxId, @orgName, @reportId, @contactInfo, @rangeBegin, @rangeEnd, @policyDomain, @policyType, @policyMode,
        @policyString, @mxHosts, @successful, @failed, @failures, @attachmentName, @rawGz, @ingestedAt)`);
    const out = { added: 0, duplicates: 0, ids: [] };
    db.transaction(() => {
      for (const p of parsed.policies) {
        const result = stmt.run({
          messageId: messageId || null,
          mailboxId: mailboxId || "env",
          orgName: parsed.orgName,
          reportId: parsed.reportId,
          contactInfo: parsed.contactInfo || null,
          rangeBegin: parsed.rangeBegin,
          rangeEnd: parsed.rangeEnd,
          policyDomain: p.policyDomain || "",
          policyType: p.policyType || null,
          policyMode: policyMode(p.policyString),
          policyString: JSON.stringify(p.policyString || []),
          mxHosts: JSON.stringify(p.mxHosts || []),
          successful: p.successful || 0,
          failed: p.failed || 0,
          failures: JSON.stringify(p.failures || []),
          attachmentName: attachmentName || null,
          rawGz,
          ingestedAt: now()
        });
        if (result.changes) {
          out.added += 1;
          out.ids.push(Number(result.lastInsertRowid));
        } else {
          out.duplicates += 1;
        }
      }
    })();
    return out;
  }

  function tlsFilter(filter = {}) {
    const clauses = [];
    const params = [];
    const from = toInt(filter.from);
    const to = toInt(filter.to);
    if (from !== null) { clauses.push("t.range_begin >= ?"); params.push(from); }
    if (to !== null) { clauses.push("t.range_begin < ?"); params.push(to); }
    if (filter.domain) { clauses.push("t.policy_domain = ?"); params.push(String(filter.domain).toLowerCase()); }
    if (filter.mailbox) { clauses.push("t.mailbox_id = ?"); params.push(String(filter.mailbox)); }
    const q = filter.q && String(filter.q).trim();
    if (q) {
      const like = likePattern(q);
      const cols = ["t.org_name", "t.policy_domain", "t.failures", "t.mx_hosts"];
      clauses.push(`(${cols.map((c) => `${c} LIKE ? ESCAPE '\\'`).join(" OR ")})`);
      params.push(...Array(cols.length).fill(like));
    }
    return { sql: clauses.length ? clauses.join(" AND ") : "1=1", params };
  }

  function shapeTls(row, { full = false } = {}) {
    const failures = parseJson(row.failures, []);
    const out = {
      id: row.id,
      messageId: row.message_id,
      mailboxId: row.mailbox_id,
      orgName: row.org_name,
      reportId: row.report_id,
      contactInfo: row.contact_info,
      rangeBegin: row.range_begin,
      rangeEnd: row.range_end,
      policyDomain: row.policy_domain || null,
      policyType: row.policy_type,
      policyMode: row.policy_mode,
      mxHosts: parseJson(row.mx_hosts, []),
      successful: row.successful,
      failed: row.failed,
      failureTypes: [...new Set(failures.map((f) => f.resultType))],
      attachmentName: row.attachment_name,
      ingestedAt: row.ingested_at
    };
    if (full) {
      out.policyString = parseJson(row.policy_string, []);
      out.failures = failures;
    }
    return out;
  }

  function tlsReports(filter = {}, { page = 1, pageSize = 50 } = {}) {
    const f = tlsFilter(filter);
    const size = Math.min(Math.max(1, toInt(pageSize, 50)), 1000);
    const offset = (Math.max(1, toInt(page, 1)) - 1) * size;
    const total = db.prepare(`SELECT COUNT(*) AS n FROM tls_reports t WHERE ${f.sql}`).get(...f.params).n;
    const rows = db.prepare(`SELECT t.id, t.message_id, t.mailbox_id, t.org_name, t.report_id, t.contact_info, t.range_begin, t.range_end, t.policy_domain,
        t.policy_type, t.policy_mode, t.mx_hosts, t.successful, t.failed, t.failures, t.attachment_name, t.ingested_at
      FROM tls_reports t WHERE ${f.sql} ORDER BY t.range_begin DESC, t.id DESC LIMIT ? OFFSET ?`).all(...f.params, size, offset);
    return { total, page: Math.max(1, toInt(page, 1)), pageSize: size, rows: rows.map((r) => shapeTls(r)) };
  }

  function tlsReportById(id) {
    const row = db.prepare("SELECT * FROM tls_reports WHERE id = ?").get(id);
    return row ? shapeTls(row, { full: true }) : null;
  }

  function tlsReportRaw(id) {
    const row = db.prepare("SELECT raw_gz, attachment_name, org_name, report_id FROM tls_reports WHERE id = ?").get(id);
    if (!row || !row.raw_gz) return null;
    return { json: zlib.gunzipSync(row.raw_gz).toString("utf8"), name: row.attachment_name || `${row.org_name}-${row.report_id}.json` };
  }

  /** Totals for the period plus failures by result type, receiving MX and sending MTA. */
  function tlsSummary(filter = {}) {
    const f = tlsFilter(filter);
    const totals = db.prepare(`
      SELECT COUNT(*) AS reports, COUNT(DISTINCT t.org_name) AS reporters, COUNT(DISTINCT t.policy_domain) AS domains,
             COALESCE(SUM(t.successful), 0) AS successful, COALESCE(SUM(t.failed), 0) AS failed,
             MIN(t.range_begin) AS firstWindow, MAX(t.range_end) AS lastWindow,
             SUM(CASE WHEN t.policy_mode = 'enforce' THEN 1 ELSE 0 END) AS enforceReports,
             SUM(CASE WHEN t.policy_mode = 'testing' THEN 1 ELSE 0 END) AS testingReports,
             SUM(CASE WHEN t.policy_type = 'no-policy-found' THEN 1 ELSE 0 END) AS noPolicyReports
      FROM tls_reports t WHERE ${f.sql}`).get(...f.params);
    const grouped = (expr) => db.prepare(`
      SELECT ${expr} AS key, SUM(json_extract(d.value, '$.failedSessionCount')) AS sessions, COUNT(DISTINCT t.id) AS reports
      FROM tls_reports t, json_each(t.failures) d WHERE ${f.sql}
      GROUP BY key ORDER BY sessions DESC LIMIT 25`).all(...f.params).filter((r) => r.key !== null);
    const days = db.prepare(`
      SELECT date(t.range_begin, 'unixepoch') AS day, SUM(t.successful) AS successful, SUM(t.failed) AS failed
      FROM tls_reports t WHERE ${f.sql} GROUP BY day ORDER BY day`).all(...f.params);
    return {
      ...totals,
      byType: grouped("json_extract(d.value, '$.resultType')").map((r) => ({ resultType: r.key, sessions: r.sessions, reports: r.reports })),
      byMx: grouped("json_extract(d.value, '$.receivingMxHostname')").map((r) => ({ host: r.key, sessions: r.sessions, reports: r.reports })),
      bySender: grouped("json_extract(d.value, '$.sendingMtaIp')").map((r) => ({ ip: r.key, sessions: r.sessions, reports: r.reports })),
      days
    };
  }

  function tlsCount() {
    return db.prepare("SELECT COUNT(*) AS n FROM tls_reports").get().n;
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

  /** Closes open alerts of one type and key because the condition went away; returns how many. */
  function resolveAlerts(type, key, { note = "resolved" } = {}) {
    return db.prepare("UPDATE alerts SET acknowledged_at = ?, acknowledged_by = ? WHERE type = ? AND key = ? AND acknowledged_at IS NULL")
      .run(now(), `auto: ${note}`, type, String(key)).changes;
  }

  // --- monitoring: DNS history, reporter cadence, ingestion --------------------

  /** Domains with reports whose window ended after `since`, busiest first. */
  function activeDomains({ since = 0, limit = 50 } = {}) {
    return db.prepare(`
      SELECT domain, SUM(messages) AS messages, MAX(range_end) AS lastSeen
      FROM reports WHERE range_end >= ? GROUP BY domain ORDER BY messages DESC LIMIT ?`).all(since, limit);
  }

  function dnsLatest(domain, kind, selector = "") {
    return db.prepare("SELECT * FROM dns_history WHERE domain = ? AND kind = ? AND selector = ? ORDER BY last_seen DESC, id DESC LIMIT 1")
      .get(String(domain).toLowerCase(), kind, selector || "") || null;
  }

  /**
   * Records one observation of a record. An unchanged value extends the current
   * row's window; a new value (or a record that appeared or vanished) starts a new
   * row. Returns { changed, previous, row } where previous is the row superseded,
   * null the first time the record is seen.
   */
  function observeDnsRecord({ domain, kind, selector = "", found, value, at = now() }) {
    const d = String(domain).toLowerCase();
    const s = selector || "";
    const v = found ? String(value) : null;
    const latest = dnsLatest(d, kind, s);
    if (latest && Boolean(latest.found) === Boolean(found) && latest.value === v) {
      db.prepare("UPDATE dns_history SET last_seen = ? WHERE id = ?").run(at, latest.id);
      return { changed: false, previous: null, row: { ...latest, last_seen: at } };
    }
    const result = db.prepare("INSERT INTO dns_history (domain, kind, selector, found, value, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(d, kind, s, found ? 1 : 0, v, at, at);
    return { changed: true, previous: latest, row: db.prepare("SELECT * FROM dns_history WHERE id = ?").get(Number(result.lastInsertRowid)) };
  }

  /** A domain's record history, newest first, including DKIM keys on its subdomains. */
  function dnsHistory(domain, { limit = 100 } = {}) {
    const d = String(domain).toLowerCase();
    return db.prepare("SELECT * FROM dns_history WHERE domain = ? OR (kind = 'dkim' AND domain LIKE ? ESCAPE '\\') ORDER BY first_seen DESC, id DESC LIMIT ?")
      .all(d, `%.${d.replace(/[\\%_]/g, "\\$&")}`, limit);
  }

  /**
   * How regularly each reporting service has been sending, judged on the 30 days
   * before its most recent report: how many reports, and the median gap in days
   * between the days it reported on. Looks back `days` days from `now`.
   */
  function reporterCadence({ now: at = now(), days = 120, window = 30 } = {}) {
    const since = at - days * DAY_SECONDS;
    const rows = db.prepare(`
      SELECT org_name AS orgName, CAST(range_end / ${DAY_SECONDS} AS INTEGER) AS day, COUNT(*) AS n, MAX(range_end) AS lastEnd
      FROM reports WHERE range_end >= ? GROUP BY org_name, day ORDER BY org_name, day`).all(since);
    const domains = new Map(db.prepare("SELECT org_name AS orgName, COUNT(DISTINCT domain) AS domains FROM reports WHERE range_end >= ? GROUP BY org_name").all(since).map((r) => [r.orgName, r.domains]));
    const byOrg = new Map();
    for (const row of rows) {
      if (!byOrg.has(row.orgName)) byOrg.set(row.orgName, []);
      byOrg.get(row.orgName).push(row);
    }
    const out = [];
    for (const [orgName, list] of byOrg) {
      const lastSeen = Math.max(...list.map((r) => r.lastEnd));
      const lastDay = Math.floor(lastSeen / DAY_SECONDS);
      const recent = list.filter((r) => r.day > lastDay - window);
      const reportsBeforeLast = recent.reduce((n, r) => n + r.n, 0);
      const gaps = [];
      for (let i = 1; i < recent.length; i += 1) gaps.push(recent[i].day - recent[i - 1].day);
      gaps.sort((a, b) => a - b);
      const medianGapDays = gaps.length ? gaps[Math.floor(gaps.length / 2)] : null;
      out.push({ orgName, lastSeen, reportsBeforeLast, reportDays: recent.length, medianGapDays, domains: domains.get(orgName) || 0 });
    }
    return out.sort((a, b) => b.reportsBeforeLast - a.reportsBeforeLast);
  }

  /** When the newest report was stored and how far its window reached; null with no reports. */
  function lastIngest() {
    const row = db.prepare("SELECT MAX(ingested_at) AS ingestedAt, MAX(range_end) AS rangeEnd, COUNT(*) AS reports FROM reports").get();
    return row && row.reports ? row : null;
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

  // --- backup, restore, re-processing ------------------------------------------

  /** A consistent copy of the database written to `dest` with SQLite's online backup. */
  async function snapshot(dest) {
    await db.backup(dest);
    return dest;
  }

  /**
   * Replaces every table's contents with those of another database file, in one
   * transaction, without closing this connection. The file must already be at the
   * current schema (see upgradeFile). Returns row counts per table.
   */
  function importFrom(file) {
    const escaped = String(file).replace(/'/g, "''");
    db.exec(`ATTACH DATABASE '${escaped}' AS src`);
    try {
      // The audit log is this instance's history and stays; everything else is replaced.
      const tables = db.prepare("SELECT name FROM main.sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> 'audit_log'").all().map((r) => r.name);
      const srcTables = new Set(db.prepare("SELECT name FROM src.sqlite_master WHERE type = 'table'").all().map((r) => r.name));
      const counts = {};
      db.exec("PRAGMA foreign_keys = OFF");
      try {
        db.transaction(() => {
          for (const t of tables) {
            db.exec(`DELETE FROM main."${t}"`);
            if (srcTables.has(t)) {
              const cols = db.prepare(`PRAGMA main.table_info("${t}")`).all().map((c) => c.name);
              const srcCols = new Set(db.prepare(`PRAGMA src.table_info("${t}")`).all().map((c) => c.name));
              const shared = cols.filter((c) => srcCols.has(c)).map((c) => `"${c}"`).join(", ");
              if (shared) db.exec(`INSERT INTO main."${t}" (${shared}) SELECT ${shared} FROM src."${t}"`);
            }
            counts[t] = db.prepare(`SELECT COUNT(*) AS n FROM main."${t}"`).get().n;
          }
          const seq = db.prepare("SELECT name FROM src.sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'").get();
          if (seq) {
            db.exec("DELETE FROM main.sqlite_sequence");
            db.exec("INSERT INTO main.sqlite_sequence SELECT * FROM src.sqlite_sequence");
          }
        })();
      } finally {
        db.exec("PRAGMA foreign_keys = ON");
      }
      compiledSenders = null;
      return counts;
    } finally {
      db.exec("DETACH DATABASE src");
    }
  }

  const reprocessTx = db.transaction((id, parsed) => {
    const { policy, records } = parsed;
    let messages = 0;
    let passed = 0;
    for (const r of records) {
      messages += r.count;
      if (r.passed) passed += r.count;
    }
    db.prepare("DELETE FROM records WHERE report_id = ?").run(id);
    for (const r of records) {
      stmts.insertRecord.run({
        reportId: id,
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
    db.prepare(`UPDATE reports SET messages = @messages, passed = @passed, adkim = @adkim, aspf = @aspf, p = @p, sp = @sp, pct = @pct, fo = @fo
      WHERE id = @id`).run({ id, messages, passed, adkim: policy.adkim, aspf: policy.aspf, p: policy.p, sp: policy.sp, pct: policy.pct, fo: policy.fo });
    return { messages, passed, records: records.length };
  });

  /** Re-parses one stored report's XML with the current parser and rewrites its records. */
  function reprocessReport(id) {
    const row = db.prepare("SELECT id, xml_gz FROM reports WHERE id = ?").get(id);
    if (!row || !row.xml_gz) return null;
    const xml = zlib.gunzipSync(row.xml_gz).toString("utf8");
    const parsed = parseAggregateReport(xml);
    return reprocessTx(id, parsed);
  }

  /** Ids of every report that still has its XML (purged ones cannot be re-processed). */
  function reprocessableIds() {
    return db.prepare("SELECT id FROM reports WHERE xml_gz IS NOT NULL ORDER BY id").all().map((r) => r.id);
  }

  // --- audit log ------------------------------------------------------------------

  function audit({ username, action, target, detail, ip, at } = {}) {
    db.prepare("INSERT INTO audit_log (at, username, action, target, detail, ip) VALUES (?, ?, ?, ?, ?, ?)")
      .run(at || now(), username || null, String(action), target === undefined || target === null ? null : String(target), detail === undefined || detail === null ? null : String(detail), ip || null);
  }

  /** Newest first; `before` (an id) pages backwards. */
  function auditLog({ limit = 100, before = null, action = null, username = null } = {}) {
    const clauses = [];
    const params = [];
    if (before) { clauses.push("id < ?"); params.push(before); }
    if (action) { clauses.push("action LIKE ?"); params.push(`${action}%`); }
    if (username) { clauses.push("username = ?"); params.push(username); }
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const rows = db.prepare(`SELECT * FROM audit_log ${where} ORDER BY id DESC LIMIT ?`).all(...params, limit + 1);
    return { entries: rows.slice(0, limit), more: rows.length > limit };
  }

  function close() {
    db.close();
  }

  return {
    db,
    snapshot,
    importFrom,
    reprocessReport,
    reprocessableIds,
    audit,
    auditLog,
    hasMessage,
    recordMessage,
    insertReport,
    latestMessageReceivedAt,
    summary,
    ips,
    ipDetail,
    ipDays,
    records,
    reports,
    reportById,
    reportXml,
    reporters,
    subdomains,
    scorecard,
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
    insertForensic,
    forensics,
    forensicById,
    forensicCount,
    insertTlsReport,
    tlsReports,
    tlsReportById,
    tlsReportRaw,
    tlsSummary,
    tlsCount,
    insertAlert,
    openAlerts,
    recentAlerts,
    openAlertCount,
    alertExists,
    ackAlert,
    ackAllAlerts,
    resolveAlerts,
    activeDomains,
    dnsLatest,
    observeDnsRecord,
    dnsHistory,
    reporterCadence,
    lastIngest,
    newFailingSources,
    newReporters,
    spikeCandidates,
    getSetting,
    setSetting,
    close
  };
}

/**
 * Opens a database file on its own, brings it to the current schema and checks
 * its integrity, then closes it. Used on an uploaded backup before importing it.
 * Returns { schemaVersion, reports, records, messages }.
 */
function upgradeFile(file) {
  const other = new Database(file);
  try {
    const kind = other.prepare("PRAGMA integrity_check").get();
    const verdict = kind ? Object.values(kind)[0] : "unknown";
    if (verdict !== "ok") {
      throw new Error(`The database in the backup fails SQLite's integrity check: ${verdict}`);
    }
    if (!other.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'reports'").get()) {
      throw new Error("The backup does not contain a DMARC analyzer database.");
    }
    other.exec(SCHEMA);
    other.exec(ALERTS_SCHEMA);
    migrate(other);
    return {
      schemaVersion: other.pragma("user_version", { simple: true }),
      reports: other.prepare("SELECT COUNT(*) AS n FROM reports").get().n,
      records: other.prepare("SELECT COUNT(*) AS n FROM records").get().n,
      messages: other.prepare("SELECT COUNT(*) AS n FROM messages").get().n
    };
  } finally {
    other.close();
  }
}

module.exports = { openDatabase, buildFilter, upgradeFile, DISPOSITIONS };
