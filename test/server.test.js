/**
 * HTTP API tests: boots the real server with a seeded database and exercises the
 * analysis endpoints, filter parsing and CSV export through a signed-in session.
 */
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { createChecker } = require("./helpers/assert");
const { openDatabase } = require("../db");
const { parseAggregateReport } = require("../dmarc-parser");
const { parseFilter, parseTime, toCsv } = require("../server");

const { check, report } = createChecker("Server: analysis API, filters, CSV");
const PROJECT = path.join(__dirname, "..");
const APP_PORT = Number(process.env.TEST_SERVER_PORT) || 3987;
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-server-"));
const EX = path.join(PROJECT, "examples");

// --- pure helpers (no server needed) -------------------------------------------

check("parseTime: unix seconds", parseTime("1758153600", "x") === 1758153600);
check("parseTime: date is UTC midnight", parseTime("2025-09-18", "x") === 1758153600);
check("parseTime: iso timestamp", parseTime("2025-09-18T12:00:00Z", "x") === 1758196800);
check("parseTime: empty is null", parseTime("", "x") === null && parseTime(undefined, "x") === null);
let threw = null;
try { parseTime("yesterday", "from"); } catch (e) { threw = e; }
check("parseTime: garbage throws naming the field", threw && /from/.test(threw.message));
threw = null;
try { parseFilter({ from: "2025-09-20", to: "2025-09-10" }); } catch (e) { threw = e; }
check("parseFilter: to before from throws", Boolean(threw));
check("parseFilter: domain lower-cased", parseFilter({ domain: " Example.COM " }).domain === "example.com");
check("parseFilter: empty", JSON.stringify(parseFilter({})) === JSON.stringify({ from: null, to: null, domain: null }));

const csv = toCsv([{
  rangeBegin: 1758153600, rangeEnd: 1758239999, orgName: "google.com", domain: "example.com", sourceIp: "1.2.3.4", ptr: null,
  count: 3, passed: false, disposition: "quarantine", dkimEval: "fail", spfEval: "fail", headerFrom: "example.com",
  envelopeFrom: null, envelopeTo: null, dkimDomain: null, spfDomain: "spam, inc", reasons: [{ type: "other", comment: "say \"hi\"" }]
}]);
const csvLines = csv.split("\r\n");
check("csv: header + row + trailing newline", csvLines.length === 3 && csvLines[0].startsWith("window_begin,") && csvLines[2] === "");
check("csv: quoting", csvLines[1].includes("\"spam, inc\"") && csvLines[1].includes("\"other: say \"\"hi\"\"\""));
check("csv: fail column", csvLines[1].split(",")[7] === "fail");

// --- seed a database the server will open ----------------------------------------

const seed = openDatabase({ dataDir: DATA_DIR });
const googleXml = fs.readFileSync(path.join(EX, "google-aggregate.xml"), "utf8");
const microsoftXml = fs.readFileSync(path.join(EX, "microsoft-aggregate.xml"), "utf8");
seed.recordMessage({ graphId: "m1", receivedAt: 1758300000, subject: "google", fromAddr: "g@google.com", status: "ingested" });
seed.recordMessage({ graphId: "m2", receivedAt: 1758310000, subject: "ms", fromAddr: "d@microsoft.com", status: "ingested" });
seed.recordMessage({ graphId: "m3", receivedAt: 1758320000, subject: "broken", fromAddr: "x@y.z", status: "error", error: "no date_range" });
const gId = seed.insertReport({ messageId: "m1", attachmentName: "google.zip", parsed: parseAggregateReport(googleXml), xml: googleXml }).reportId;
seed.insertReport({ messageId: "m2", attachmentName: "ms.xml.gz", parsed: parseAggregateReport(microsoftXml), xml: microsoftXml });
seed.setPtr("192.0.2.99", "mail.badhost.test");
seed.close();

let cookie = null;
let csrf = null;

async function req(pathname, { method = "GET", body, raw = false } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (cookie) headers.Cookie = cookie;
  if (csrf) headers["X-CSRF-Token"] = csrf;
  const res = await fetch(`http://127.0.0.1:${APP_PORT}${pathname}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const setCookie = res.headers.get("set-cookie");
  if (setCookie) {
    const m = setCookie.match(/dmarc_session=([^;]*)/);
    if (m) cookie = `dmarc_session=${m[1]}`;
  }
  if (raw) {
    return { status: res.status, text: await res.text(), headers: res.headers };
  }
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

async function waitForServer(tries = 60) {
  for (let i = 0; i < tries; i += 1) {
    try {
      const r = await fetch(`http://127.0.0.1:${APP_PORT}/api/auth/me`);
      if (r.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("server did not start");
}

(async () => {
  const app = spawn("node", ["server.js"], {
    cwd: PROJECT,
    env: { ...process.env, PORT: String(APP_PORT), DATA_DIR, SYNC_INTERVAL_MINUTES: "0", GRAPH_TENANT_ID: "", GRAPH_CLIENT_ID: "", GRAPH_CLIENT_SECRET: "", DMARC_MAILBOX: "" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  app.stderr.on("data", (d) => console.error("[app stderr]", d.toString().trim()));

  try {
    await waitForServer();
    const setup = await req("/api/auth/setup", { method: "POST", body: { username: "admin", password: "correct-horse-battery" } });
    csrf = setup.body.csrfToken;
    check("signed in", setup.status === 200 && Boolean(csrf));

    // --- status ---
    const status = await req("/api/status");
    check("status: graph unconfigured with missing list", status.body.graph.configured === false && status.body.graph.missing.length === 4);
    check("status: never exposes a secret field", !JSON.stringify(status.body).includes("clientSecret"));
    check("status: scheduler off", status.body.scheduler.enabled === false);
    check("status: stats and errors", status.body.stats.reports.reports === 2 && status.body.errors.length === 1 && status.body.errors[0].graph_id === "m3");

    // --- summary and filters ---
    const all = await req("/api/summary");
    check("summary: totals", all.body.totals.messages === 53 && all.body.totals.failed === 10 && all.body.totals.failPct === 18.9);
    check("summary: days", all.body.days.length === 1 && all.body.days[0].day === "2025-09-18");
    const windowed = await req("/api/summary?from=2025-09-18&to=2025-09-19");
    check("summary: date filter includes the window", windowed.body.totals.messages === 53);
    const outside = await req("/api/summary?from=2025-09-19");
    check("summary: date filter excludes", outside.body.totals.messages === 0 && outside.body.days.length === 0);
    const bad = await req("/api/summary?from=nonsense");
    check("summary: bad date is 400", bad.status === 400 && /from/.test(bad.body.error));
    const inverted = await req("/api/summary?from=2025-09-20&to=2025-09-01");
    check("summary: inverted range is 400", inverted.status === 400);
    const byDomain = await req("/api/summary?domain=EXAMPLE.com");
    check("summary: domain filter", byDomain.body.totals.messages === 53);
    check("summary: other domain empty", (await req("/api/summary?domain=nope.test")).body.totals.reports === 0);

    // --- ips ---
    const ips = await req("/api/ips");
    check("ips: all sources", ips.body.ips.length === 4);
    const failing = await req("/api/ips?failing=1");
    check("ips: failing only, worst first with ptr", failing.body.ips.length === 2 && failing.body.ips[0].ip === "192.0.2.99" && failing.body.ips[0].ptr === "mail.badhost.test");
    const ipDetail = await req("/api/ips/192.0.2.99");
    check("ips: detail", ipDetail.status === 200 && ipDetail.body.records.length === 1 && ipDetail.body.records[0].reasons.length === 2);
    check("ips: unknown ip is 404", (await req("/api/ips/10.0.0.1")).status === 404);
    const v6 = await req(`/api/ips/${encodeURIComponent("2001:db8::25")}`);
    check("ips: ipv6 path", v6.status === 200 && v6.body.passed === 1);

    // --- records ---
    const failRecords = await req("/api/records?result=fail");
    check("records: fail filter", failRecords.body.total === 2 && failRecords.body.rows.every((r) => !r.passed));
    const orgRecords = await req("/api/records?org=google.com&pageSize=1&page=2");
    check("records: org + paging", orgRecords.body.total === 2 && orgRecords.body.rows.length === 1 && orgRecords.body.page === 2);

    // --- reports ---
    const reports = await req("/api/reports");
    check("reports: list", reports.body.total === 2 && reports.body.rows[0].failed !== undefined && reports.body.rows.some((r) => r.receivedAt === 1758300000));
    const one = await req(`/api/reports/${gId}`);
    check("reports: detail", one.status === 200 && one.body.records.length === 2 && one.body.subject === "google");
    check("reports: missing is 404", (await req("/api/reports/9999")).status === 404);
    const xml = await req(`/api/reports/${gId}/xml`, { raw: true });
    check("reports: xml download", xml.status === 200 && xml.text === googleXml && /attachment; filename="google\.xml"/.test(xml.headers.get("content-disposition")));
    check("reports: xml missing is 404", (await req("/api/reports/9999/xml", { raw: true })).status === 404);

    // --- reporters / domains ---
    const reporters = await req("/api/reporters");
    check("reporters", reporters.body.reporters.length === 2 && reporters.body.reporters[0].orgName === "google.com");
    const domains = await req("/api/domains");
    check("domains", domains.body.domains.length === 1 && domains.body.domains[0].domain === "example.com");

    // --- csv ---
    const csvRes = await req("/api/export/records.csv?result=fail", { raw: true });
    check("csv export", csvRes.status === 200 && /text\/csv/.test(csvRes.headers.get("content-type")) && csvRes.text.split("\r\n").length === 4);
    check("csv export honours filters", csvRes.text.includes("192.0.2.99") && !csvRes.text.includes("203.0.113.10"));

    // --- sync without configuration ---
    const syncStart = await req("/api/sync", { method: "POST", body: {} });
    check("sync: starts a job", syncStart.status === 200 && Boolean(syncStart.body.jobId));
    await new Promise((r) => setTimeout(r, 300));
    const job = await req(`/api/sync/${syncStart.body.jobId}`);
    check("sync: unconfigured job fails with guidance", job.body.status === "failed" && /GRAPH_TENANT_ID/.test(job.body.error));
    check("sync: bad since is 400", (await req("/api/sync", { method: "POST", body: { since: "whenever" } })).status === 400);
    check("sync: unknown job is 404", (await req("/api/sync/999")).status === 404);
    const runs = await req("/api/sync/runs");
    check("sync: run history", runs.body.runs.length === 1 && runs.body.runs[0].trigger === "manual" && /GRAPH_TENANT_ID/.test(runs.body.runs[0].error_text));

    const test = await req("/api/graph/test", { method: "POST", body: {} });
    check("graph test reports not configured", test.body.ok === false && /Not configured/.test(test.body.detail));

    check("static page served", (await fetch(`http://127.0.0.1:${APP_PORT}/`)).status === 200);
  } finally {
    const exited = new Promise((resolve) => app.once("exit", resolve));
    app.kill();
    await exited;
    fs.rmSync(DATA_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }

  process.exit(report() ? 0 : 1);
})().catch((e) => {
  console.error("FATAL", e);
  fs.rmSync(DATA_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  process.exit(1);
});
