const fs = require("fs");
const path = require("path");
const express = require("express");

const { createAuth } = require("./auth-routes");
const { resolveTlsOptions } = require("./tls-setup");
const { openDatabase } = require("./db");
const { createGraphClient, configFromEnv } = require("./graph");
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
const CSV_ROW_CAP = 50000;

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

fs.mkdirSync(DATA_DIR, { recursive: true });
const authGuard = createAuth({ dataDir: DATA_DIR });
const db = openDatabase({ dataDir: DATA_DIR });
const graph = createGraphClient(configFromEnv());
const sync = createSync({ db, graph, backfillDays: BACKFILL_DAYS });

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
  return { from, to, domain };
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
  res.json({
    graph: graph.describe(),
    scheduler: { intervalMinutes: SYNC_INTERVAL_MINUTES, enabled: SYNC_INTERVAL_MINUTES > 0 && graph.isConfigured() },
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
  const { job, alreadyRunning } = sync.runSync({ trigger: "manual", since });
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

app.post("/api/graph/test", authGuard.requireAdmin, route(async (req, res) => {
  res.json(await graph.testConnection());
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

    const g = graph.describe();
    if (g.configured) {
      console.log(`Mailbox: ${g.mailbox} (folder "${g.folder}", tenant ${g.tenantId})`);
      if (SYNC_INTERVAL_MINUTES > 0) {
        console.log(`Sync: every ${SYNC_INTERVAL_MINUTES} minute(s); first run in 10 seconds. Backfill window: ${BACKFILL_DAYS} days.`);
        sync.startScheduler(SYNC_INTERVAL_MINUTES);
      } else {
        console.log("Sync: scheduled sync is off (SYNC_INTERVAL_MINUTES=0); use Sync now in the app.");
      }
    } else {
      console.log(`Mailbox: not configured - set ${g.missing.join(", ")} to enable syncing.`);
    }

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
