const fs = require("fs");
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

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

fs.mkdirSync(DATA_DIR, { recursive: true });
const authGuard = createAuth({ dataDir: DATA_DIR });
const db = openDatabase({ dataDir: DATA_DIR });
const envGraph = configFromEnv();
const mailboxes = createMailboxStore({ dataDir: DATA_DIR, env: envGraph, loginBase: envGraph.loginBase, graphBase: envGraph.graphBase });
const geoip = createGeoIp({
  dataDir: DATA_DIR,
  cityDb: process.env.GEOIP_CITY_DB || undefined,
  asnDb: process.env.GEOIP_ASN_DB || undefined,
  online: String(process.env.GEOIP_ONLINE || "true").toLowerCase() !== "false"
});
const sync = createSync({
  db,
  mailboxes,
  geoip,
  backfillDays: BACKFILL_DAYS,
  onRunFinished: (job) => {
    const { created } = evaluateAfterSync({ db, addedReportIds: job.addedReportIds });
    if (created.length) {
      console.log(`alerts: ${created.length} new (${created.map((a) => a.type).join(", ")})`);
    }
  }
});
const dnsRecords = createDnsRecords();
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
    configured: list.some((m) => m.enabled),
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
app.get("/api/weekly", route(async (req, res) => {
  let end;
  try {
    end = req.query.end ? parseTime(req.query.end, "end") : null;
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
  const DAY = 86400;
  const today = Math.floor(Date.now() / 1000 / DAY) * DAY;
  const to = (end === null ? today : Math.floor(end / DAY) * DAY) + DAY; // week ending on this day, inclusive
  const from = to - 7 * DAY;
  const base = { domain: req.query.domain ? String(req.query.domain).toLowerCase() : null, mailbox: req.query.mailbox || null, excludeForwards: false };

  const thisWeek = db.summary({ ...base, from, to });
  const lastWeek = db.summary({ ...base, from: from - 7 * DAY, to: from });
  const ips = db.ips({ ...base, from, to }, { limit: 5000 });
  const w = {
    domain: base.domain,
    thisWeek: { from, to, totals: thisWeek.totals, days: thisWeek.days, reporters: thisWeek.topReporters },
    lastWeek: { from: from - 7 * DAY, to: from, totals: lastWeek.totals, days: lastWeek.days },
    newSources: db.firstSeenSources({ ...base, from, to }).slice(0, 10),
    topFailing: ips.filter((r) => r.failed > 0).sort((a, b) => b.failed - a.failed).slice(0, 5),
    topForwards: ips.filter((r) => r.likelyForwards > 0).sort((a, b) => b.likelyForwards - a.likelyForwards).slice(0, 5),
    openAlerts: db.openAlertCount()
  };
  w.text = weeklyText(w);
  res.json(w);
}));

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
 * Everything needed to decide whether the domain is ready for p=reject: the DNS
 * records with warnings, and what rejecting would have done in the period.
 */
app.get("/api/policy", route(async (req, res) => {
  const filter = filterFrom(req);
  const domain = String(req.query.domain || filter.domain || "").trim().toLowerCase();
  if (!/^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(domain)) {
    return res.status(400).json({ error: "Pick a domain first." });
  }
  const refresh = String(req.query.refresh || "") === "1";
  const scoped = { ...filter, domain };

  const [dmarc, spf] = await Promise.all([
    dnsRecords.getDmarc(domain, { refresh }).catch((error) => ({ domain, found: false, error: error.message, tags: {}, warnings: [`DNS lookup failed: ${error.message}`] })),
    dnsRecords.getSpf(domain, { refresh }).catch((error) => ({ domain, found: false, error: error.message, networks: [], warnings: [`DNS lookup failed: ${error.message}`], errors: [] }))
  ]);

  // Which of the mailbox addresses the reports actually reach.
  const addresses = mailboxes.list().map((m) => m.mailbox.toLowerCase());
  const rua = (dmarc.tags && dmarc.tags.rua) || [];
  const ruaToUs = rua.some((a) => addresses.includes(String(a).toLowerCase()));
  const dmarcWarnings = [...(dmarc.warnings || [])];
  if (dmarc.found && rua.length && addresses.length && !ruaToUs) {
    dmarcWarnings.push(`rua= points at ${rua.join(", ")}, none of which is a mailbox this analyzer reads (${addresses.join(", ")}).`);
  }

  // Sources in the period, annotated with whether SPF authorises them.
  const spfNets = compileSenders((spf.networks || []).map((n) => ({ pattern: n.cidr, via: n.via })));
  const rows = db.ips(scoped, { limit: 5000 }).map((r) => {
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
  const selectors = db.dkimSelectors(domain, filter).filter((s) => s.signingDomain === domain || String(s.signingDomain || "").endsWith(`.${domain}`) || domain.endsWith(`.${s.signingDomain}`));
  const dkim = await Promise.all(selectors.slice(0, 20).map(async (s) => {
    const check = await dnsRecords.checkDkim(s.signingDomain, s.selector, { refresh }).catch((error) => ({ found: false, error: error.message }));
    return { ...s, ...check };
  }));

  res.json({
    domain,
    mailboxAddresses: addresses,
    dmarc: { ...dmarc, warnings: dmarcWarnings, ruaToUs },
    spf: { ...spf, networks: (spf.networks || []).length },
    dkim,
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
  res.json({ ok: true, added, skipped, sender: added[0] || null });
}));

app.put("/api/known-senders/:id", authGuard.requireWriter, route(async (req, res) => {
  res.json({ ok: true, sender: db.updateKnownSender(positiveInt(req.params.id, 0), req.body || {}) });
}));

app.delete("/api/known-senders/:id", authGuard.requireAdmin, route(async (req, res) => {
  db.removeKnownSender(positiveInt(req.params.id, 0));
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

app.get("/api/mailboxes", authGuard.requireAdmin, route(async (req, res) => {
  res.json({ mailboxes: mailboxes.list() });
}));

app.post("/api/mailboxes", authGuard.requireAdmin, route(async (req, res) => {
  const mailbox = mailboxes.add(req.body || {});
  console.log(`mailboxes: ${req.user?.username || "admin"} added ${mailbox.mailbox} (${mailbox.id})`);
  res.json({ ok: true, mailbox });
}));

app.put("/api/mailboxes/:id", authGuard.requireAdmin, route(async (req, res) => {
  const mailbox = mailboxes.update(req.params.id, req.body || {});
  res.json({ ok: true, mailbox });
}));

app.delete("/api/mailboxes/:id", authGuard.requireAdmin, route(async (req, res) => {
  mailboxes.remove(req.params.id);
  res.json({ ok: true });
}));

app.post("/api/mailboxes/:id/test", authGuard.requireAdmin, route(async (req, res) => {
  if (!mailboxes.get(req.params.id)) {
    return res.status(404).json({ error: "No such mailbox." });
  }
  res.json(await mailboxes.testConnection(req.params.id));
}));

// --- analysis --------------------------------------------------------------

app.get("/api/summary", route(async (req, res) => {
  res.json(db.summary(filterFrom(req)));
}));

app.get("/api/ips", route(async (req, res) => {
  const filter = filterFrom(req);
  const failingOnly = String(req.query.failing || "") === "1";
  res.json({ ips: db.ips(filter, { failingOnly, limit: positiveInt(req.query.limit, 500) }) });
}));

app.get("/api/ips/:ip", route(async (req, res) => {
  const detail = db.ipDetail(req.params.ip, filterFrom(req));
  if (!detail) {
    return res.status(404).json({ error: "No records for that IP in the selected range." });
  }
  res.json(detail);
}));

app.get("/api/records", route(async (req, res) => {
  const filter = filterFrom(req);
  res.json(db.records(filter, {
    result: req.query.result,
    ip: req.query.ip,
    org: req.query.org,
    page: positiveInt(req.query.page, 1),
    pageSize: positiveInt(req.query.pageSize, 100)
  }));
}));

app.get("/api/reports", route(async (req, res) => {
  const filter = filterFrom(req);
  res.json(db.reports(filter, {
    org: req.query.org,
    page: positiveInt(req.query.page, 1),
    pageSize: positiveInt(req.query.pageSize, 50)
  }));
}));

app.get("/api/reports/:id", route(async (req, res) => {
  const report = db.reportById(positiveInt(req.params.id, 0));
  if (!report) {
    return res.status(404).json({ error: "No such report." });
  }
  res.json(report);
}));

app.get("/api/reports/:id/xml", route(async (req, res) => {
  const result = db.reportXml(positiveInt(req.params.id, 0));
  if (!result) {
    return res.status(404).json({ error: "No XML stored for that report." });
  }
  res.setHeader("Content-Type", "application/xml; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${result.fileName.replace(/[^\w.!@-]+/g, "_")}"`);
  res.send(result.xml);
}));

app.get("/api/reporters", route(async (req, res) => {
  res.json({ reporters: db.reporters(filterFrom(req)) });
}));

app.get("/api/domains", route(async (req, res) => {
  res.json({ domains: db.domains() });
}));

app.get("/api/export/records.csv", route(async (req, res) => {
  const filter = filterFrom(req);
  const { rows, total } = db.records(filter, { result: req.query.result, ip: req.query.ip, org: req.query.org, page: 1, pageSize: CSV_ROW_CAP });
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", "attachment; filename=\"dmarc-records.csv\"");
  if (total > rows.length) {
    res.setHeader("X-Truncated", String(total));
  }
  res.send(toCsv(rows));
}));

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
