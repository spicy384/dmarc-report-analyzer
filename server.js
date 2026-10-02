const fs = require("fs");
const os = require("os");
const path = require("path");
const express = require("express");

const { createAuth } = require("./auth-routes");
const { resolveTlsOptions } = require("./tls-setup");
const { openDatabase } = require("./db");
const { configFromEnv } = require("./graph");
const { createMailboxStore } = require("./mailboxes");
const { createDnsRecords } = require("./dns-records");
const { evaluateAfterSync } = require("./alerts");
const { compileSenders, findSender } = require("./ipmatch");
const { createGeoIp } = require("./geoip");
const { createRetention } = require("./retention");
const { createBackup, restoreBackup } = require("./backup");
const { createNotifier } = require("./notify");
const { createMonitor } = require("./monitor");
const { createIngest } = require("./ingest");
const { createScratchStore } = require("./scratch");
const { createUpdateChecker } = require("./version");
const pkg = require("./package.json");

// Manually uploaded files are stored under this pseudo-mailbox id.
const UPLOAD_MAILBOX = "upload";
const { createSync, publicJob } = require("./sync");

const app = express();
const PORT = process.env.PORT || 3000;
// Override with DATA_DIR when running in a container so the database lives on a volume.
const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(__dirname, "data");

const SYNC_INTERVAL_MINUTES = process.env.SYNC_INTERVAL_MINUTES === undefined
  ? 60
  : Number(process.env.SYNC_INTERVAL_MINUTES) || 0;
const BACKFILL_DAYS = Number(process.env.BACKFILL_DAYS) > 0 ? Number(process.env.BACKFILL_DAYS) : 90;
// 0 keeps everything; N rolls reports older than N months into daily totals and drops their records and XML.
const RETENTION_MONTHS = Number(process.env.RETENTION_MONTHS) > 0 ? Number(process.env.RETENTION_MONTHS) : 0;
const CSV_ROW_CAP = 50000;

// Security headers. The page loads only its own scripts and styles; inline styles
// are allowed because the chart and drawers set element styles from JavaScript,
// and data: images carry the authenticator QR code.
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'"
].join("; ");
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", CSP);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  next();
});

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

fs.mkdirSync(DATA_DIR, { recursive: true });
// The audit callback runs per request, by which time the database below exists.
const authGuard = createAuth({ dataDir: DATA_DIR, audit: (entry) => db.audit(entry) });
const db = openDatabase({ dataDir: DATA_DIR });
const envGraph = configFromEnv();
const mailboxes = createMailboxStore({ dataDir: DATA_DIR, env: envGraph, loginBase: envGraph.loginBase, graphBase: envGraph.graphBase });
const geoip = createGeoIp({
  dataDir: DATA_DIR,
  cityDb: process.env.GEOIP_CITY_DB || undefined,
  asnDb: process.env.GEOIP_ASN_DB || undefined,
  online: String(process.env.GEOIP_ONLINE || "true").toLowerCase() !== "false"
});
/** After reports were stored (by a sync or an upload): evaluate alerts, then notify. */
function afterIngest(addedReportIds = []) {
  const created = [...evaluateAfterSync({ db, addedReportIds }).created];
  // Also the moment to notice that nothing arrived (or that it did again).
  try {
    created.push(...monitor.checkHealth().created);
  } catch (error) {
    console.warn(`monitor: ${error.message}`);
  }
  if (created.length) {
    console.log(`alerts: ${created.length} new (${created.map((a) => a.type).join(", ")})`);
    notifier.notifyAlerts(created).catch((error) => console.warn(`notify: ${error.message}`));
  }
}

const ingest = createIngest({ db });
// One-time analyses of uploaded files: in-memory databases, never written to DATA_DIR.
const scratches = createScratchStore({ openDatabase, createIngest, createSync, mainDb: db, geoip });
// Running version (package.json, plus the commit the image was built from) and the daily
// look at the registry for a newer release. UPDATE_CHECK=false keeps it entirely offline.
const updates = createUpdateChecker({
  version: pkg.version,
  commit: process.env.APP_COMMIT || null,
  buildDate: process.env.APP_BUILD_DATE || null,
  image: process.env.UPDATE_IMAGE || "ghcr.io/spicy384/dmarc-report-analyzer",
  enabled: String(process.env.UPDATE_CHECK || "true").toLowerCase() !== "false"
});
const sync = createSync({
  db,
  mailboxes,
  geoip,
  ingest,
  backfillDays: BACKFILL_DAYS,
  onRunFinished: (job) => afterIngest(job.addedReportIds)
});
// Webhook notifications (Teams, Slack or generic JSON) for new alerts and the weekly summary.
const notifier = createNotifier({ db, buildWeekly: (options) => buildWeekly(options), appUrl: process.env.APP_URL || "" });
const dnsRecords = createDnsRecords();
// Daily DNS snapshots (record drift) and the "nothing arrived" checks.
const monitor = createMonitor({ db, dnsRecords, mailboxes });
const retention = createRetention({ db, months: RETENTION_MONTHS });

// The sign-in endpoints must be reachable while signed out; everything else under /api is gated.
app.use(authGuard.router);
app.use("/api", authGuard.requireAuth);

// --- helpers ---------------------------------------------------------------

/**
 * Turns a query string date into unix seconds. Accepts unix seconds, a YYYY-MM-DD
 * date (treated as UTC midnight) or any ISO timestamp. Returns null when absent
 * and throws on garbage so the caller can answer 400.
 */
function parseTime(value, label) {
  if (value === undefined || value === null || value === "") {
    return null;
  }
  const str = String(value).trim();
  if (/^\d{9,}$/.test(str)) {
    return Number(str);
  }
  const iso = /^\d{4}-\d{2}-\d{2}$/.test(str) ? `${str}T00:00:00Z` : str;
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) {
    throw new Error(`${label} is not a date: ${str}`);
  }
  return Math.floor(ms / 1000);
}

/** The { from, to, domain } filter every analysis endpoint accepts. `to` is exclusive. */
function parseFilter(query = {}) {
  const from = parseTime(query.from, "from");
  const to = parseTime(query.to, "to");
  if (from !== null && to !== null && to < from) {
    throw new Error("to must not be before from");
  }
  const domain = query.domain ? String(query.domain).trim().toLowerCase() : null;
  const q = query.q ? String(query.q).trim().slice(0, 200) : null;
  const excludeForwards = String(query.hideForwards || "") === "1";
  const mailbox = query.mailbox ? String(query.mailbox).trim().slice(0, 40) : null;
  return { from, to, domain, q: q || null, excludeForwards, mailbox: mailbox || null };
}

function positiveInt(value, fallback) {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

function csvCell(value) {
  if (value === null || value === undefined) {
    return "";
  }
  const s = Array.isArray(value) ? value.join(" ") : String(value);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, "\"\"")}"` : s;
}

function toCsv(rows) {
  const header = ["window_begin", "window_end", "reporter", "domain", "source_ip", "ptr", "count", "dmarc",
    "disposition", "dkim_eval", "spf_eval", "header_from", "envelope_from", "envelope_to", "dkim_domain", "spf_domain", "reasons"];
  const lines = [header.join(",")];
  for (const r of rows) {
    lines.push([
      new Date(r.rangeBegin * 1000).toISOString(),
      new Date(r.rangeEnd * 1000).toISOString(),
      r.orgName, r.domain, r.sourceIp, r.ptr, r.count, r.passed ? "pass" : "fail",
      r.disposition, r.dkimEval, r.spfEval, r.headerFrom, r.envelopeFrom, r.envelopeTo, r.dkimDomain, r.spfDomain,
      (r.reasons || []).map((x) => x.comment ? `${x.type}: ${x.comment}` : x.type).join("; ")
    ].map(csvCell).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}

/** Wraps a handler so filter parsing errors become 400s and anything else a 500. */
function route(handler) {
  return async (req, res) => {
    try {
      await handler(req, res);
    } catch (error) {
      const status = error.status || (error.isFilter ? 400 : 500);
      res.status(status).json({ error: error.message });
    }
  };
}

function filterFrom(req) {
  try {
    return parseFilter(req.query);
  } catch (error) {
    error.isFilter = true;
    throw error;
  }
}

// --- status & sync ---------------------------------------------------------

app.get("/api/status", route(async (req, res) => {
  const lastRuns = new Map(db.lastRunsByMailbox().map((r) => [r.mailbox_id, r]));
  const counts = new Map(db.mailboxCounts().map((c) => [c.id, c]));
  const list = mailboxes.list().map((m) => ({ ...m, lastRun: lastRuns.get(m.id) || null, counts: counts.get(m.id) || null }));
  res.json({
    mailboxes: list,
    mailboxCounts: db.mailboxCounts(),
    geoip: { ...geoip.describe(), stats: db.geoStats() },
    retention: retention.describe(),
    forensicCount: db.forensicCount(),
    tlsCount: db.tlsCount(),
    version: updates.describe(),
    configured: list.some((m) => m.enabled),
    // First-run walkthrough: offered while no mailbox exists (no env variables, nothing
    // added in the app) until an administrator dismisses it.
    setup: { needed: list.length === 0, dismissed: db.getSetting("setup_dismissed") === "1" },
    scheduler: { intervalMinutes: SYNC_INTERVAL_MINUTES, enabled: SYNC_INTERVAL_MINUTES > 0 && sync.anyConfigured() },
    backfillDays: BACKFILL_DAYS,
    currentJob: publicJob(sync.currentJob()),
    lastRun: db.lastRun(),
    stats: db.stats(),
    errors: db.messagesWithErrors(20)
  });
}));

app.post("/api/sync", authGuard.requireWriter, route(async (req, res) => {
  let since = null;
  if (req.body && req.body.since) {
    try {
      since = parseTime(req.body.since, "since");
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }
  }
  const mailboxId = req.body && req.body.mailboxId ? String(req.body.mailboxId) : null;
  if (mailboxId && !mailboxes.get(mailboxId)) {
    return res.status(404).json({ error: "No such mailbox." });
  }
  const { job, alreadyRunning } = sync.runSync({ trigger: "manual", since, mailboxId });
  res.json({ jobId: job.id, alreadyRunning, job: publicJob(job) });
}));

app.get("/api/sync/runs", route(async (req, res) => {
  res.json({ runs: db.runs(positiveInt(req.query.limit, 20)) });
}));

app.get("/api/sync/:id", route(async (req, res) => {
  const job = sync.getJob(req.params.id);
  if (!job) {
    return res.status(404).json({ error: "No such sync job." });
  }
  res.json(publicJob(job));
}));

// --- analysis router -------------------------------------------------------------
//
// Every endpoint that reads report data lives on this router and takes the
// database from req.db. It is mounted twice: under /api for the live store, and
// under /api/scratch/:id for a one-time analysis of uploaded files that is never
// written to disk (see scratch.js).
const analysis = express.Router();

// --- TLS reports (RFC 8460) ----------------------------------------------------

analysis.get("/tls", route(async (req, res) => {
  const filter = filterFrom(req);
  res.json(req.db.tlsReports(filter, { page: positiveInt(req.query.page, 1), pageSize: positiveInt(req.query.pageSize, 50) }));
}));

analysis.get("/tls/summary", route(async (req, res) => {
  res.json(req.db.tlsSummary(filterFrom(req)));
}));

analysis.get("/tls/:id", route(async (req, res) => {
  const row = req.db.tlsReportById(positiveInt(req.params.id, 0));
  if (!row) {
    return res.status(404).json({ error: "No such TLS report." });
  }
  res.json(row);
}));

analysis.get("/tls/:id/json", route(async (req, res) => {
  const raw = req.db.tlsReportRaw(positiveInt(req.params.id, 0));
  if (!raw) {
    return res.status(404).json({ error: "No such TLS report, or its JSON was not kept." });
  }
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${raw.name.replace(/[^\w.!@-]+/g, "_")}"`);
  res.send(raw.json);
}));

// --- manual upload ---------------------------------------------------------------

/**
 * One file per request, raw body, name in X-File-Name (URL-encoded). The file is
 * treated exactly like a mailbox attachment: aggregate XML in any container, a TLS
 * report, or a whole .eml (forensic report or carrier of attachments).
 */
app.post("/api/upload", authGuard.requireWriter, express.raw({ type: () => true, limit: "200mb" }), route(async (req, res) => {
  const bytes = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  if (!bytes.length) {
    return res.status(400).json({ error: "No file was uploaded." });
  }
  let name = String(req.get("X-File-Name") || "");
  try {
    name = decodeURIComponent(name);
  } catch { /* keep as sent */ }
  name = path.basename(name).slice(0, 200);
  const messageId = `${UPLOAD_MAILBOX}:${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const result = ingest.ingestFile({ bytes, name, messageId, mailboxId: UPLOAD_MAILBOX });
  const status = result.found ? "ingested" : result.problems.length ? "error" : "no_report";
  db.recordMessage({
    graphId: messageId,
    mailboxId: UPLOAD_MAILBOX,
    receivedAt: Math.floor(Date.now() / 1000),
    subject: name || "uploaded file",
    fromAddr: req.user?.username || null,
    status,
    error: result.problems.length ? result.problems.join("; ").slice(0, 2000) : null
  });
  if (result.aggregate.ids.length) {
    afterIngest(result.aggregate.ids);
  }
  const duplicates = result.aggregate.duplicates + result.tls.duplicates + result.forensic.duplicates;
  auditFrom(req, "reports.upload", name || "(unnamed)", `${result.aggregate.added} aggregate, ${result.tls.added} TLS, ${result.forensic.added} forensic added; ${duplicates} duplicate(s); ${result.problems.length} problem(s)`);
  res.json({ name, status, ...result });
}));

// --- forensic reports -----------------------------------------------------------

analysis.get("/forensic", route(async (req, res) => {
  const filter = filterFrom(req);
  res.json(req.db.forensics(filter, { ip: req.query.ip, page: positiveInt(req.query.page, 1), pageSize: positiveInt(req.query.pageSize, 50) }));
}));

analysis.get("/forensic/:id", route(async (req, res) => {
  const row = req.db.forensicById(positiveInt(req.params.id, 0));
  if (!row) {
    return res.status(404).json({ error: "No such forensic report." });
  }
  res.json(row);
}));

// --- weekly summary ------------------------------------------------------------

function pctText(n) {
  return `${Number(n || 0).toFixed(1)}%`;
}

function changeText(current, previous, { pct = false } = {}) {
  const diff = (current || 0) - (previous || 0);
  if (pct) {
    return Math.abs(diff) < 0.05 ? "unchanged" : `${diff > 0 ? "+" : ""}${diff.toFixed(1)} pts`;
  }
  if (!previous) {
    return diff ? `+${diff}` : "unchanged";
  }
  return diff === 0 ? "unchanged" : `${diff > 0 ? "+" : ""}${Math.round((diff / previous) * 100)}%`;
}

function weeklyText(w) {
  const t = w.thisWeek.totals;
  const p = w.lastWeek.totals;
  const day = (s) => new Date(s * 1000).toISOString().slice(0, 10);
  const lines = [];
  lines.push(`DMARC weekly summary${w.domain ? ` for ${w.domain}` : ""}: ${day(w.thisWeek.from)} to ${day(w.thisWeek.to - 1)}`);
  lines.push("");
  lines.push(`Messages: ${t.messages} (${changeText(t.messages, p.messages)} vs previous week)`);
  lines.push(`DMARC pass rate: ${pctText(t.passPct)} (${changeText(t.passPct, p.passPct, { pct: true })})`);
  lines.push(`Failures: ${t.failed} (${changeText(t.failed, p.failed)}), of which ${t.likelyForwards} likely forwards`);
  lines.push(`Quarantined: ${t.quarantined}, rejected: ${t.rejected}`);
  lines.push(`Failing sources: ${t.failingIps} of ${t.sourceIps} (${changeText(t.failingIps, p.failingIps)})`);
  lines.push(`Reports: ${t.reports} from ${t.reporters} reporting services`);
  if (w.newSources.length) {
    lines.push("");
    lines.push("New sources this week:");
    for (const s of w.newSources) {
      lines.push(`  - ${s.ip}${s.ptr ? ` (${s.ptr})` : ""}${s.asOrg ? ` ${s.asOrg}` : ""}: ${s.failed} of ${s.total} failed${s.sender ? ` - ${s.sender.label}` : ""}`);
    }
  }
  if (w.topFailing.length) {
    lines.push("");
    lines.push("Top failing sources:");
    for (const s of w.topFailing) {
      lines.push(`  - ${s.ip}${s.ptr ? ` (${s.ptr})` : ""}: ${s.failed} failed of ${s.total}${s.sender ? ` - ${s.sender.label}` : ""}${s.likelyForwards ? ` (${s.likelyForwards} likely forwards)` : ""}`);
    }
  }
  if (w.openAlerts) {
    lines.push("");
    lines.push(`${w.openAlerts} open alert${w.openAlerts === 1 ? "" : "s"} awaiting acknowledgement.`);
  }
  return lines.join("\n");
}

/** This week against last week, plus a plain-text version to paste into email or chat. */
analysis.get("/weekly", route(async (req, res) => {
  let end;
  try {
    end = req.query.end ? parseTime(req.query.end, "end") : null;
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
  res.json(buildWeekly({ db: req.db, end, domain: req.query.domain ? String(req.query.domain).toLowerCase() : null, mailbox: req.query.mailbox || null }));
}));

/** The week ending on `end` (unix seconds, default today) against the week before, plus its plain-text form. */
function buildWeekly({ db: store = db, end = null, domain = null, mailbox = null } = {}) {
  const DAY = 86400;
  const today = Math.floor(Date.now() / 1000 / DAY) * DAY;
  const to = (end === null ? today : Math.floor(end / DAY) * DAY) + DAY; // week ending on this day, inclusive
  const from = to - 7 * DAY;
  const base = { domain, mailbox, excludeForwards: false };

  const thisWeek = store.summary({ ...base, from, to });
  const lastWeek = store.summary({ ...base, from: from - 7 * DAY, to: from });
  const ips = store.ips({ ...base, from, to }, { limit: 5000 });
  const w = {
    domain: base.domain,
    thisWeek: { from, to, totals: thisWeek.totals, days: thisWeek.days, reporters: thisWeek.topReporters },
    lastWeek: { from: from - 7 * DAY, to: from, totals: lastWeek.totals, days: lastWeek.days },
    newSources: store.firstSeenSources({ ...base, from, to }).slice(0, 10),
    topFailing: ips.filter((r) => r.failed > 0).sort((a, b) => b.failed - a.failed).slice(0, 5),
    topForwards: ips.filter((r) => r.likelyForwards > 0).sort((a, b) => b.likelyForwards - a.likelyForwards).slice(0, 5),
    openAlerts: store.openAlertCount()
  };
  w.text = weeklyText(w);
  return w;
}

// --- geoip ---------------------------------------------------------------------

/** Re-resolves every source IP, e.g. after the GeoLite2 files were added. Runs in the background. */
app.post("/api/geoip/refresh", authGuard.requireAdmin, route(async (req, res) => {
  if (!geoip.isEnabled()) {
    return res.status(400).json({ error: "GeoIP is off: no GeoLite2 files were found and GEOIP_ONLINE is false." });
  }
  const all = Boolean(req.body && req.body.all);
  sync.lookupGeo({ all }).then((n) => console.log(`geoip: resolved ${n} address(es)`)).catch((error) => console.warn(`geoip: ${error.message}`));
  res.json({ ok: true, started: true, all });
}));

// --- policy readiness ----------------------------------------------------------

function topSources(rows, key, limit = 5) {
  return rows
    .filter((r) => r[key] > 0)
    .sort((a, b) => b[key] - a[key])
    .slice(0, limit)
    .map((r) => ({ ip: r.ip, ptr: r.ptr, count: r[key], sender: r.sender ? r.sender.label : null, spfPassed: r.spfPassed, dkimPassed: r.dkimPassed, total: r.total }));
}

/**
 * Ad-hoc DNS lookup: DMARC, SPF, MX and addresses for a domain, reverse DNS for
 * an IP. For an IP the response also says what the analyzer already knows about
 * it (label, reverse name from sync, geo, report totals) so the two views agree.
 */
app.get("/api/lookup", route(async (req, res) => {
  const refresh = String(req.query.refresh || "") === "1";
  const result = await dnsRecords.lookup(req.query.q, { refresh });
  if (result.type === "ip") {
    const [seen] = db.ips({}, { ip: result.query, limit: 1 });
    result.known = db.senderFor(result.query, seen ? seen.ptr : null);
    result.seen = seen ? {
      ptr: seen.ptr, total: seen.total, failed: seen.failed, likelyForwards: seen.likelyForwards || 0,
      firstSeen: seen.firstSeen, lastSeen: seen.lastSeen, country: seen.country || null, countryCode: seen.countryCode || null,
      city: seen.city || null, asn: seen.asn || null, asOrg: seen.asOrg || null
    } : null;
  }
  res.json(result);
}));

/**
 * Everything needed to decide whether the domain is ready for p=reject: the DNS
 * records with warnings, and what rejecting would have done in the period.
 */
analysis.get("/policy", route(async (req, res) => {
  const filter = filterFrom(req);
  const domain = String(req.query.domain || filter.domain || "").trim().toLowerCase();
  if (!/^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(domain)) {
    return res.status(400).json({ error: "Pick a domain first." });
  }
  const refresh = String(req.query.refresh || "") === "1";
  const scoped = { ...filter, domain };

  const [dmarc, spf, mtaSts, tlsRpt] = await Promise.all([
    dnsRecords.getDmarc(domain, { refresh }).catch((error) => ({ domain, found: false, error: error.message, tags: {}, warnings: [`DNS lookup failed: ${error.message}`] })),
    dnsRecords.getSpf(domain, { refresh }).catch((error) => ({ domain, found: false, error: error.message, networks: [], warnings: [`DNS lookup failed: ${error.message}`], errors: [] })),
    dnsRecords.getMtaSts(domain, { refresh }).catch((error) => ({ domain, found: false, error: error.message, policy: null, mxCoverage: [], warnings: [`DNS lookup failed: ${error.message}`] })),
    dnsRecords.getTlsRpt(domain, { refresh }).catch((error) => ({ domain, found: false, error: error.message, rua: [], warnings: [`DNS lookup failed: ${error.message}`] }))
  ]);

  // Which of the mailbox addresses the reports actually reach.
  const addresses = mailboxes.list().map((m) => m.mailbox.toLowerCase());
  const tlsRua = (tlsRpt.rua || []).map((a) => String(a).toLowerCase());
  const tlsRptToUs = tlsRua.some((a) => addresses.includes(a));
  const tlsRptWarnings = [...(tlsRpt.warnings || [])];
  if (tlsRpt.found && tlsRua.length && addresses.length && !tlsRptToUs) {
    tlsRptWarnings.push(`rua= points at ${tlsRua.join(", ")}, none of which is a mailbox this analyzer reads (${addresses.join(", ")}).`);
  }
  const rua = (dmarc.tags && dmarc.tags.rua) || [];
  const ruaToUs = rua.some((a) => addresses.includes(String(a).toLowerCase()));
  const dmarcWarnings = [...(dmarc.warnings || [])];
  if (dmarc.found && rua.length && addresses.length && !ruaToUs) {
    dmarcWarnings.push(`rua= points at ${rua.join(", ")}, none of which is a mailbox this analyzer reads (${addresses.join(", ")}).`);
  }

  // Sources in the period, annotated with whether SPF authorises them.
  const spfNets = compileSenders((spf.networks || []).map((n) => ({ pattern: n.cidr, via: n.via })));
  const rows = req.db.ips(scoped, { limit: 5000 }).map((r) => {
    const inSpf = findSender(spfNets, r.ip, null);
    const nonForwardFailed = r.failed - (r.likelyForwards || 0);
    return { ...r, inSpf: Boolean(inSpf), spfVia: inSpf ? inSpf.via : null, nonForwardFailed };
  });

  const groups = { ours: [], vendor: [], other: [], unknown: [] };
  for (const r of rows) {
    groups[r.sender ? r.sender.kind : "unknown"].push(r);
  }
  const sum = (list, key) => list.reduce((n, r) => n + (r[key] || 0), 0);
  const reject = {
    legitimateRejected: { messages: sum(groups.ours, "nonForwardFailed") + sum(groups.vendor, "nonForwardFailed"), sources: topSources([...groups.ours, ...groups.vendor], "nonForwardFailed") },
    spoofingBlocked: { messages: sum(groups.unknown, "nonForwardFailed") + sum(groups.other, "nonForwardFailed"), sources: topSources([...groups.unknown, ...groups.other], "nonForwardFailed") },
    forwardsLost: { messages: sum(rows, "likelyForwards"), sources: topSources(rows, "likelyForwards") },
    passing: sum(rows, "passed"),
    total: sum(rows, "total"),
    unlabelledFailingSources: groups.unknown.filter((r) => r.nonForwardFailed > 0).length
  };

  const yoursOutsideSpf = [...groups.ours, ...groups.vendor].filter((r) => !r.inSpf && r.spfPassed < r.total);
  const failingInsideSpf = rows.filter((r) => r.inSpf && r.nonForwardFailed > 0);

  // DKIM selectors seen for the domain, checked in DNS.
  const selectors = req.db.dkimSelectors(domain, filter).filter((s) => s.signingDomain === domain || String(s.signingDomain || "").endsWith(`.${domain}`) || domain.endsWith(`.${s.signingDomain}`));
  const dkim = await Promise.all(selectors.slice(0, 20).map(async (s) => {
    const check = await dnsRecords.checkDkim(s.signingDomain, s.selector, { refresh }).catch((error) => ({ found: false, error: error.message }));
    // When the daily snapshot has tracked this key, say how long the current value has stood.
    const latest = req.db.dnsLatest(s.signingDomain, "dkim", s.selector);
    return { ...s, ...check, unchangedSince: latest && Boolean(latest.found) === Boolean(check.found) && (!check.found || latest.value === check.record) ? latest.first_seen : null };
  }));
  const sinceFor = (kind, found, value) => {
    const latest = req.db.dnsLatest(domain, kind);
    return latest && Boolean(latest.found) === Boolean(found) && (!found || latest.value === value) ? latest.first_seen : null;
  };

  res.json({
    domain,
    mailboxAddresses: addresses,
    dmarc: { ...dmarc, warnings: dmarcWarnings, ruaToUs, unchangedSince: sinceFor("dmarc", dmarc.found, dmarc.record) },
    spf: { ...spf, networks: (spf.networks || []).length, unchangedSince: sinceFor("spf", spf.found, spf.record) },
    dkim,
    transport: {
      mtaSts: { ...mtaSts, unchangedSince: sinceFor("mta_sts", mtaSts.found, mtaSts.record), policyUnchangedSince: mtaSts.policyText ? sinceFor("mta_sts_policy", true, mtaSts.policyText.trim()) : null },
      tlsRpt: { ...tlsRpt, warnings: tlsRptWarnings, toUs: tlsRptToUs, unchangedSince: sinceFor("tlsrpt", tlsRpt.found, tlsRpt.record) },
      tlsSummary: req.db.tlsSummary(scoped)
    },
    history: req.db.dnsHistory(domain, { limit: 50 }),
    reject,
    yoursOutsideSpf: yoursOutsideSpf.map((r) => ({ ip: r.ip, ptr: r.ptr, sender: r.sender.label, total: r.total, spfPassed: r.spfPassed, failed: r.failed })),
    failingInsideSpf: failingInsideSpf.map((r) => ({ ip: r.ip, ptr: r.ptr, sender: r.sender ? r.sender.label : null, via: r.spfVia, failed: r.nonForwardFailed, dkimPassed: r.dkimPassed, total: r.total }))
  });
}));

// --- alerts ------------------------------------------------------------------

app.get("/api/alerts", route(async (req, res) => {
  const open = String(req.query.open || "1") !== "0";
  res.json({ alerts: open ? db.openAlerts(positiveInt(req.query.limit, 100)) : db.recentAlerts(positiveInt(req.query.limit, 50)), openCount: db.openAlertCount() });
}));

app.post("/api/alerts/ack-all", authGuard.requireWriter, route(async (req, res) => {
  res.json({ ok: true, acknowledged: db.ackAllAlerts(req.user?.username || null) });
}));

app.post("/api/alerts/:id/ack", authGuard.requireWriter, route(async (req, res) => {
  if (!db.ackAlert(positiveInt(req.params.id, 0), req.user?.username || null)) {
    return res.status(404).json({ error: "No such open alert." });
  }
  res.json({ ok: true, openCount: db.openAlertCount() });
}));

// --- version -----------------------------------------------------------------

app.get("/api/version", route(async (req, res) => {
  res.json(updates.describe());
}));

/** Asks the registry now instead of waiting for the daily check. */
app.post("/api/version/check", authGuard.requireAdmin, route(async (req, res) => {
  res.json(await updates.check());
}));

// --- monitoring --------------------------------------------------------------

app.get("/api/monitor", route(async (req, res) => {
  res.json(monitor.describe());
}));

/** Runs the DNS snapshot and the health checks now, whatever the clock says. */
app.post("/api/monitor/run", authGuard.requireAdmin, route(async (req, res) => {
  const result = await monitor.runAll({ force: true });
  if (result.created.length) {
    notifier.notifyAlerts(result.created).catch((error) => console.warn(`notify: ${error.message}`));
  }
  auditFrom(req, "monitor.run", `${result.domains} domain(s)`, `${result.created.length} alert(s) created, ${result.resolved.length} resolved${result.errors.length ? `, ${result.errors.length} lookup error(s)` : ""}`);
  res.json({ ...result, created: result.created.map((a) => ({ id: a.id, type: a.type, key: a.key, severity: a.severity, title: a.title })), status: monitor.describe() });
}));

app.get("/api/dns-history", route(async (req, res) => {
  const domain = String(req.query.domain || "").trim().toLowerCase();
  if (!/^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(domain)) {
    return res.status(400).json({ error: "Pick a domain first." });
  }
  res.json({ domain, history: db.dnsHistory(domain, { limit: positiveInt(req.query.limit, 100) }) });
}));

// --- known senders -----------------------------------------------------------

app.get("/api/known-senders", route(async (req, res) => {
  res.json({ senders: db.knownSenders() });
}));

app.post("/api/known-senders", authGuard.requireWriter, route(async (req, res) => {
  const body = req.body || {};
  // Several at once (from the SPF import) or a single entry.
  const items = Array.isArray(body.senders) ? body.senders : [body];
  const added = [];
  const skipped = [];
  for (const item of items) {
    try {
      added.push(db.addKnownSender(item, { createdBy: req.user?.username || null, source: item.source === "spf" ? "spf" : "manual" }));
    } catch (error) {
      if (items.length === 1) throw error;
      skipped.push({ pattern: item.pattern, error: error.message });
    }
  }
  for (const a of added) auditFrom(req, "sender.add", a.pattern, `${a.kind}: ${a.label}${a.source === "spf" ? " (from SPF)" : ""}`);
  res.json({ ok: true, added, skipped, sender: added[0] || null });
}));

app.put("/api/known-senders/:id", authGuard.requireWriter, route(async (req, res) => {
  const sender = db.updateKnownSender(positiveInt(req.params.id, 0), req.body || {});
  auditFrom(req, "sender.update", sender.pattern, `${sender.kind}: ${sender.label}`);
  res.json({ ok: true, sender });
}));

app.delete("/api/known-senders/:id", authGuard.requireAdmin, route(async (req, res) => {
  const gone = db.knownSenders().find((k) => k.id === positiveInt(req.params.id, 0));
  db.removeKnownSender(positiveInt(req.params.id, 0));
  auditFrom(req, "sender.remove", gone ? gone.pattern : req.params.id, gone ? `${gone.kind}: ${gone.label}` : null);
  res.json({ ok: true });
}));

/** Proposes known-sender entries from a domain's SPF record; nothing is stored until the user accepts. */
app.post("/api/known-senders/from-spf", authGuard.requireWriter, route(async (req, res) => {
  const domain = String((req.body && req.body.domain) || "").trim().toLowerCase();
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) {
    return res.status(400).json({ error: "Enter a domain name." });
  }
  const spf = await dnsRecords.getSpf(domain, { refresh: Boolean(req.body && req.body.refresh) });
  const existing = new Set(db.knownSenders().map((s) => s.pattern));
  const seen = new Set();
  const proposals = [];
  for (const n of spf.networks) {
    const cidr = String(n.cidr).toLowerCase();
    if (seen.has(cidr)) continue;
    seen.add(cidr);
    proposals.push({ pattern: cidr, kind: "ours", label: `SPF ${domain}: ${n.via}`.slice(0, 80), source: "spf", exists: existing.has(cidr) });
  }
  res.json({ domain, found: spf.found, record: spf.record, lookups: spf.lookups, tooManyLookups: spf.tooManyLookups, errors: spf.errors, warnings: spf.warnings, proposals });
}));

// --- mailboxes (admin) -------------------------------------------------------

// The walkthrough can be put away for good; it can still be reopened from the sync panel.
app.post("/api/setup/dismiss", authGuard.requireAdmin, route(async (req, res) => {
  db.setSetting("setup_dismissed", "1");
  res.json({ ok: true });
}));

app.get("/api/mailboxes", authGuard.requireAdmin, route(async (req, res) => {
  res.json({ mailboxes: mailboxes.list() });
}));

app.post("/api/mailboxes", authGuard.requireAdmin, route(async (req, res) => {
  const mailbox = mailboxes.add(req.body || {});
  console.log(`mailboxes: ${req.user?.username || "admin"} added ${mailbox.mailbox} (${mailbox.id})`);
  auditFrom(req, "mailbox.add", mailbox.mailbox, `${mailbox.name}; ${mailbox.typeLabel}; ${mailbox.authMethod}`);
  res.json({ ok: true, mailbox });
}));

app.put("/api/mailboxes/:id", authGuard.requireAdmin, route(async (req, res) => {
  const mailbox = mailboxes.update(req.params.id, req.body || {});
  const body = req.body || {};
  const plain = ["name", "tenantId", "clientId", "authMethod", "mailbox", "folder", "enabled", "host", "port", "security", "username", "tlsVerify", "region", "bucket", "prefix", "accessKeyId", "endpoint"];
  const secret = { clientSecret: "client secret", certPem: "certificate", password: "password", serviceAccountKey: "service account key", secretAccessKey: "secret access key" };
  const touched = plain.filter((k) => body[k] !== undefined).concat(Object.keys(secret).filter((k) => body[k]).map((k) => secret[k]));
  auditFrom(req, "mailbox.update", mailbox.mailbox, `${mailbox.name}; changed ${touched.join(", ") || "nothing"}`);
  res.json({ ok: true, mailbox });
}));

app.delete("/api/mailboxes/:id", authGuard.requireAdmin, route(async (req, res) => {
  const gone = mailboxes.get(req.params.id);
  mailboxes.remove(req.params.id);
  auditFrom(req, "mailbox.remove", gone ? gone.mailbox : req.params.id, gone ? gone.name : null);
  res.json({ ok: true });
}));

app.post("/api/mailboxes/:id/test", authGuard.requireAdmin, route(async (req, res) => {
  if (!mailboxes.get(req.params.id)) {
    return res.status(404).json({ error: "No such mailbox." });
  }
  res.json(await mailboxes.testConnection(req.params.id));
}));

// --- maintenance: backup, restore, re-process --------------------------------

const APP_VERSION = require("./package.json").version;

/** Writes an audit entry attributed to the signed-in user. */
function auditFrom(req, action, target, detail) {
  try {
    db.audit({ username: req.user?.username || null, ip: req.ip || null, action, target, detail });
  } catch (error) {
    console.error(`audit: could not record ${action}: ${error.message}`);
  }
}

function syncRunning() {
  const job = sync.currentJob();
  return Boolean(job && job.status === "running");
}

// Re-processing runs in the background in small batches; one at a time.
const reprocess = { running: false, total: 0, done: 0, changed: 0, errors: 0, startedAt: null, finishedAt: null, lastError: null };

async function runReprocess() {
  const ids = db.reprocessableIds();
  Object.assign(reprocess, { running: true, total: ids.length, done: 0, changed: 0, errors: 0, startedAt: Math.floor(Date.now() / 1000), finishedAt: null, lastError: null });
  const BATCH = 25;
  for (let i = 0; i < ids.length; i += BATCH) {
    for (const id of ids.slice(i, i + BATCH)) {
      try {
        const before = db.reportById(id);
        const result = db.reprocessReport(id);
        if (result && before && (result.messages !== before.messages || result.passed !== before.passed || result.records !== (before.records || []).length)) {
          reprocess.changed += 1;
        }
      } catch (error) {
        reprocess.errors += 1;
        reprocess.lastError = `report ${id}: ${error.message}`;
      }
      reprocess.done += 1;
    }
    // Let requests through between batches.
    await new Promise((resolve) => setImmediate(resolve));
  }
  reprocess.running = false;
  reprocess.finishedAt = Math.floor(Date.now() / 1000);
}

app.get("/api/maintenance/status", authGuard.requireAdmin, route(async (req, res) => {
  res.json({ reprocess: { ...reprocess }, syncRunning: syncRunning(), reprocessable: db.reprocessableIds().length });
}));

app.get("/api/maintenance/backup", authGuard.requireAdmin, route(async (req, res) => {
  if (syncRunning()) {
    return res.status(409).json({ error: "A sync is running; wait for it to finish before taking a backup." });
  }
  const stamp = new Date().toISOString().replace(/[-:]/g, "").slice(0, 15).replace("T", "-");
  const tmp = path.join(os.tmpdir(), `dmarc-backup-${process.pid}-${Date.now()}.tar.gz`);
  const manifest = await createBackup({ db, dataDir: DATA_DIR, dest: tmp, version: APP_VERSION });
  auditFrom(req, "backup.download", null, `${manifest.files.join(", ")}; ${manifest.bytes} bytes`);
  res.setHeader("Content-Type", "application/gzip");
  res.setHeader("Content-Disposition", `attachment; filename="dmarc-backup-${stamp}.tar.gz"`);
  res.setHeader("Content-Length", String(manifest.bytes));
  const stream = fs.createReadStream(tmp);
  stream.on("close", () => fs.rm(tmp, { force: true }, () => {}));
  stream.pipe(res);
}));

// The archive arrives as the raw request body; it is small compared to the 1 GB cap.
app.post("/api/maintenance/restore", authGuard.requireAdmin, express.raw({ type: () => true, limit: "1gb" }), route(async (req, res) => {
  if (syncRunning() || reprocess.running) {
    return res.status(409).json({ error: "A sync or re-process is running; wait for it to finish before restoring." });
  }
  if (!Buffer.isBuffer(req.body) || req.body.length < 64) {
    return res.status(400).json({ error: "No backup file was uploaded." });
  }
  const result = restoreBackup({ db, dataDir: DATA_DIR, buffer: req.body });
  auditFrom(req, "backup.restore", null, `from ${result.manifest.createdAt}; ${result.database.reports} reports, ${result.database.messages} messages; ${result.settings.join(", ") || "no settings files"}`);
  // Accounts may have changed underneath the caller; the front end signs in again if so.
  const stillExists = Boolean(authGuard.findUser && authGuard.findUser(req.user.username));
  res.json({ ok: true, ...result, signInAgain: !stillExists });
}));

app.post("/api/maintenance/reprocess", authGuard.requireAdmin, route(async (req, res) => {
  if (reprocess.running) {
    return res.status(409).json({ error: "A re-process is already running." });
  }
  if (syncRunning()) {
    return res.status(409).json({ error: "A sync is running; wait for it to finish first." });
  }
  auditFrom(req, "reports.reprocess", null, `${db.reprocessableIds().length} reports with stored XML`);
  runReprocess().catch((error) => {
    reprocess.running = false;
    reprocess.lastError = error.message;
    reprocess.finishedAt = Math.floor(Date.now() / 1000);
  });
  res.json({ ok: true, reprocess: { ...reprocess } });
}));

// --- notifications --------------------------------------------------------------

app.get("/api/notify", authGuard.requireAdmin, route(async (req, res) => {
  res.json(notifier.settings());
}));

app.put("/api/notify", authGuard.requireAdmin, route(async (req, res) => {
  const body = req.body || {};
  // The app's own address, for the "open" link, defaults to where this request came from.
  if (body.appUrl === undefined && !notifier.settings().appUrl) {
    const proto = String(req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
    body.appUrl = `${proto}://${req.headers.host || "localhost"}`;
  }
  const saved = notifier.save(body);
  auditFrom(req, "notify.update", saved.host || "(none)", `${saved.kind}; alerts ${saved.alerts ? "on" : "off"}; weekly ${saved.weekly ? `${saved.weeklyDayName} ${saved.weeklyHour}:00` : "off"}`);
  res.json(saved);
}));

app.post("/api/notify/test", authGuard.requireAdmin, route(async (req, res) => {
  const result = await notifier.test();
  auditFrom(req, "notify.test", notifier.settings().host || "(none)", result.detail);
  res.json(result);
}));

app.post("/api/notify/weekly", authGuard.requireAdmin, route(async (req, res) => {
  const result = await notifier.maybeSendWeekly({ force: true });
  res.json(result || { ok: false, detail: "No webhook URL is configured." });
}));

app.get("/api/audit", authGuard.requireAdmin, route(async (req, res) => {
  const before = req.query.before ? positiveInt(req.query.before, 0) : null;
  res.json(db.auditLog({ limit: Math.min(positiveInt(req.query.limit, 100), 500), before: before || null, action: req.query.action ? String(req.query.action) : null, username: req.query.username ? String(req.query.username) : null }));
}));

// --- analysis --------------------------------------------------------------

analysis.get("/summary", route(async (req, res) => {
  res.json(req.db.summary(filterFrom(req)));
}));

analysis.get("/ips", route(async (req, res) => {
  const filter = filterFrom(req);
  const failingOnly = String(req.query.failing || "") === "1";
  const ips = req.db.ips(filter, { failingOnly, limit: positiveInt(req.query.limit, 500) });
  // Per-day series for sparklines, fetched in one query for every row returned.
  if (String(req.query.days || "") === "1") {
    const byIp = req.db.ipDays(filter, ips.map((r) => r.ip));
    for (const row of ips) row.days = byIp.get(row.ip) || [];
  }
  res.json({ ips });
}));

analysis.get("/ips/:ip", route(async (req, res) => {
  const detail = req.db.ipDetail(req.params.ip, filterFrom(req));
  if (!detail) {
    return res.status(404).json({ error: "No records for that IP in the selected range." });
  }
  res.json(detail);
}));

analysis.get("/records", route(async (req, res) => {
  const filter = filterFrom(req);
  res.json(req.db.records(filter, {
    result: req.query.result,
    ip: req.query.ip,
    org: req.query.org,
    page: positiveInt(req.query.page, 1),
    pageSize: positiveInt(req.query.pageSize, 100)
  }));
}));

analysis.get("/reports", route(async (req, res) => {
  const filter = filterFrom(req);
  res.json(req.db.reports(filter, {
    org: req.query.org,
    page: positiveInt(req.query.page, 1),
    pageSize: positiveInt(req.query.pageSize, 50)
  }));
}));

analysis.get("/reports/:id", route(async (req, res) => {
  const report = req.db.reportById(positiveInt(req.params.id, 0));
  if (!report) {
    return res.status(404).json({ error: "No such report." });
  }
  res.json(report);
}));

analysis.get("/reports/:id/xml", route(async (req, res) => {
  const result = req.db.reportXml(positiveInt(req.params.id, 0));
  if (!result) {
    return res.status(404).json({ error: "No XML stored for that report." });
  }
  res.setHeader("Content-Type", "application/xml; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${result.fileName.replace(/[^\w.!@-]+/g, "_")}"`);
  res.send(result.xml);
}));

analysis.get("/reporters", route(async (req, res) => {
  res.json({ reporters: req.db.reporters(filterFrom(req)) });
}));

analysis.get("/subdomains", route(async (req, res) => {
  res.json({ subdomains: req.db.subdomains(filterFrom(req)) });
}));

analysis.get("/scorecard", route(async (req, res) => {
  res.json({ domains: req.db.scorecard(filterFrom(req)) });
}));

analysis.get("/domains", route(async (req, res) => {
  res.json({ domains: req.db.domains() });
}));

analysis.get("/export/records.csv", route(async (req, res) => {
  const filter = filterFrom(req);
  const { rows, total } = req.db.records(filter, { result: req.query.result, ip: req.query.ip, org: req.query.org, page: 1, pageSize: CSV_ROW_CAP });
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", "attachment; filename=\"dmarc-records.csv\"");
  if (total > rows.length) {
    res.setHeader("X-Truncated", String(total));
  }
  res.send(toCsv(rows));
}));

// --- scratch analyses: upload, inspect, discard ----------------------------------

/** Creates a scratch analysis on the first upload, or adds to an existing one. */
async function scratchUpload(req, res, scratch) {
  const bytes = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  if (!bytes.length) {
    return res.status(400).json({ error: "No file was uploaded." });
  }
  let name = String(req.get("X-File-Name") || "");
  try {
    name = decodeURIComponent(name);
  } catch { /* keep as sent */ }
  name = path.basename(name).slice(0, 200);
  const target = scratch || scratches.create(req.user?.username || null);
  const result = await scratches.addFile(target, { bytes, name });
  res.json({ id: target.id, name, ...result, analysis: scratches.describe(target) });
}

const scratchGate = (req, res, next) => {
  const scratch = scratches.get(req.params.id, req.user?.username || null);
  if (!scratch) {
    return res.status(404).json({ error: "That analysis has expired or does not exist. Upload the files again." });
  }
  req.scratch = scratch;
  req.db = scratch.db;
  next();
};

app.post("/api/scratch/upload", express.raw({ type: () => true, limit: "200mb" }), route(async (req, res) => scratchUpload(req, res, null)));
app.post("/api/scratch/:id/upload", scratchGate, express.raw({ type: () => true, limit: "200mb" }), route(async (req, res) => scratchUpload(req, res, req.scratch)));
app.get("/api/scratch/:id", scratchGate, route(async (req, res) => {
  res.json(scratches.describe(req.scratch));
}));
app.delete("/api/scratch/:id", scratchGate, route(async (req, res) => {
  scratches.remove(req.scratch.id);
  res.json({ ok: true });
}));

app.use("/api/scratch/:id", scratchGate, analysis);
app.use("/api", (req, res, next) => {
  req.db = db;
  next();
}, analysis);

// --- boot ------------------------------------------------------------------

// Only boot when run directly, so tests can require the pure helpers below
// without starting a listener.
if (require.main === module) {
  let tlsOptions = null;
  try {
    tlsOptions = resolveTlsOptions({ dataDir: DATA_DIR });
  } catch (error) {
    // Failing loudly beats silently falling back to plain HTTP when TLS was asked for.
    console.error(`\n  !! TLS could not be configured: ${error.message}\n`);
    process.exit(1);
  }

  const scheme = tlsOptions ? "https" : "http";
  const server = tlsOptions
    ? require("https").createServer({ key: tlsOptions.key, cert: tlsOptions.cert }, app)
    : require("http").createServer(app);

  server.listen(PORT, () => {
    console.log(`DMARC Report Analyzer running at ${scheme}://localhost:${PORT}`);
    console.log(`Data directory: ${DATA_DIR}`);

    if (tlsOptions) {
      console.log(`TLS: on (${tlsOptions.mode}) - ${tlsOptions.detail}`);
      if (tlsOptions.mode === "self-signed") {
        console.log("     Self-signed: fine for a reverse proxy upstream, but browsers "
          + "connecting directly will warn.");
      }
    } else {
      console.log("TLS: off (plain HTTP)");
    }

    const boxes = mailboxes.list();
    if (boxes.length) {
      for (const m of boxes) {
        console.log(`Mailbox: ${m.mailbox} (folder "${m.folder}", tenant ${m.tenantId})${m.enabled ? "" : " - disabled"}${m.readOnly ? " - from environment" : ""}`);
      }
      if (SYNC_INTERVAL_MINUTES > 0 && boxes.some((m) => m.enabled)) {
        console.log(`Sync: every ${SYNC_INTERVAL_MINUTES} minute(s); first run in 10 seconds. Backfill window: ${BACKFILL_DAYS} days.`);
        sync.startScheduler(SYNC_INTERVAL_MINUTES);
      } else if (SYNC_INTERVAL_MINUTES > 0) {
        console.log("Sync: every mailbox is disabled; nothing is scheduled.");
      } else {
        console.log("Sync: scheduled sync is off (SYNC_INTERVAL_MINUTES=0); use Sync now in the app.");
      }
    } else {
      console.log("Mailbox: none configured - add one under Mailbox sync as an administrator, or set "
        + "GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET and DMARC_MAILBOX.");
    }

    if (retention.enabled) {
      retention.start();
      console.log(`Retention: reports older than ${RETENTION_MONTHS} month(s) are rolled up into daily totals; records and XML removed. First pass in 30 seconds, then daily.`);
    } else {
      console.log("Retention: keeping everything (set RETENTION_MONTHS to roll up old reports).");
    }
    notifier.start();
    scratches.start();
    updates.start();
    console.log(`Version: ${pkg.version}${process.env.APP_COMMIT ? ` (${String(process.env.APP_COMMIT).slice(0, 7)})` : ""}; update check ${updates.describe().enabled ? `daily against ${updates.describe().image}` : "off"}.`);
    monitor.start({ onAlerts: (created) => {
      console.log(`monitor: ${created.length} new alert(s) (${created.map((a) => a.type).join(", ")})`);
      notifier.notifyAlerts(created).catch((error) => console.warn(`notify: ${error.message}`));
    } });
    console.log("Monitoring: DNS records snapshotted daily; reporter silence and stalled ingestion checked hourly and after each sync.");

    geoip.open().then((g) => {
      const parts = [];
      if (g.cityDb) parts.push("city file");
      if (g.asnDb) parts.push("ASN file");
      if (g.online) parts.push(`online via ${g.onlineProvider}`);
      console.log(`GeoIP: ${parts.length ? parts.join(", ") : "off"}${g.problems.length ? ` (problems: ${g.problems.join("; ")})` : ""}`);
      if (!g.cityDb || !g.asnDb) {
        console.log(`        Put GeoLite2-City.mmdb and GeoLite2-ASN.mmdb in ${path.join(DATA_DIR, "geoip")} for offline lookups.`);
      }
    });

    if (!authGuard.hasUsers()) {
      console.log("Accounts: none yet - open the app to create the first administrator.");
    } else {
      console.log(`Accounts: ${authGuard.loadUsers().length} user(s) configured.`);
    }

    if (authGuard.cookieSecure) {
      console.log("Session cookie: Secure (requires HTTPS end to end - sign-in fails over plain HTTP)");
    } else if (tlsOptions) {
      console.log("Session cookie: not Secure - this app is serving HTTPS, so set COOKIE_SECURE=true");
    } else {
      console.log("Session cookie: not Secure (fine on loopback; set COOKIE_SECURE=true behind HTTPS)");
    }

    if (authGuard.trustProxyAuth) {
      console.warn(
        `\n  !! TRUST_PROXY_AUTH is ON. Anyone who can reach this port directly can\n`
        + `     impersonate any user by sending the '${authGuard.proxyUserHeader}' header.\n`
        + `     Only run this way when a reverse proxy in front strips that header from\n`
        + `     client requests and sets it itself, and the app is not otherwise reachable.\n`
      );
    }
  });

  const shutdown = () => {
    sync.stopScheduler();
    scratches.stop();
    server.close(() => {
      db.close();
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 3000).unref();
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

module.exports = { app, parseFilter, parseTime, toCsv };
