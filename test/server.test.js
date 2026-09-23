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
check("parseFilter: empty", JSON.stringify(parseFilter({})) === JSON.stringify({ from: null, to: null, domain: null, q: null, excludeForwards: false, mailbox: null }));
check("parseFilter: search and hideForwards", (() => { const f = parseFilter({ q: "  badhost ", hideForwards: "1" }); return f.q === "badhost" && f.excludeForwards === true; })());

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
    env: { ...process.env, PORT: String(APP_PORT), DATA_DIR, SYNC_INTERVAL_MINUTES: "0", GRAPH_TENANT_ID: "", GRAPH_CLIENT_ID: "", GRAPH_CLIENT_SECRET: "", DMARC_MAILBOX: "", GRAPH_LOGIN_BASE: "http://127.0.0.1:1", GRAPH_API_BASE: "http://127.0.0.1:1/v1.0" },
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
    check("status: no mailboxes configured", status.body.configured === false && Array.isArray(status.body.mailboxes) && status.body.mailboxes.length === 0);
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

    // --- search and forwards ---
    const q1 = await req("/api/summary?q=192.0.2.99");
    check("search: ip narrows the summary", q1.body.totals.messages === 7 && q1.body.totals.reports === 1);
    const q2 = await req("/api/ips?q=badhost");
    check("search: reverse dns", q2.body.ips.length === 1 && q2.body.ips[0].ip === "192.0.2.99");
    const q3 = await req("/api/reports?q=google");
    check("search: reporter on reports", q3.body.total === 1 && q3.body.rows[0].orgName === "google.com");
    const q4 = await req("/api/reporters?q=spammer");
    check("search: spf domain reaches reporters", q4.body.reporters.length === 1 && q4.body.reporters[0].orgName === "google.com");
    check("search: no match is empty, not an error", (await req("/api/summary?q=zzz")).body.totals.messages === 0);
    const hf = await req("/api/summary?hideForwards=1");
    check("hideForwards accepted", hf.status === 200 && hf.body.totals.messages === 53 && hf.body.totals.likelyForwards === 0);
    check("records expose likelyForward", (await req("/api/records?result=fail")).body.rows.every((r) => r.likelyForward === false));

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

    // --- policy readiness ---
    check("policy: domain required", (await req("/api/policy")).status === 400);
    const pol = await req("/api/policy?domain=no-such-domain-for-tests.invalid");
    check("policy: shape with no records and no reports", pol.status === 200 && pol.body.dmarc.found === false && pol.body.spf.found === false && Array.isArray(pol.body.dkim) && pol.body.reject.total === 0);
    const polEx = await req("/api/policy?domain=example.com");
    check("policy: reject breakdown from stored reports", polEx.status === 200 && polEx.body.reject.total === 53 && polEx.body.reject.spoofingBlocked.messages === 10 && polEx.body.reject.legitimateRejected.messages === 0 && polEx.body.reject.unlabelledFailingSources === 2);
    check("policy: dkim selectors checked", polEx.body.dkim.some((s) => s.selector === "selector1" && typeof s.found === "boolean"));
    check("policy: dmarc warnings is an array", Array.isArray(polEx.body.dmarc.warnings));

    // --- alerts ---
    check("alerts: none open", (await req("/api/alerts")).body.openCount === 0);
    check("alerts: ack unknown is 404", (await req("/api/alerts/999/ack", { method: "POST", body: {} })).status === 404);
    check("alerts: ack-all with nothing open", (await req("/api/alerts/ack-all", { method: "POST", body: {} })).body.acknowledged === 0);

    // --- known senders ---
    check("known senders: empty", (await req("/api/known-senders")).body.senders.length === 0);
    const ksAdd = await req("/api/known-senders", { method: "POST", body: { pattern: "203.0.113.0/24", kind: "ours", label: "Our relay" } });
    check("known senders: add", ksAdd.status === 200 && ksAdd.body.sender.id > 0 && ksAdd.body.sender.created_by === "admin");
    check("known senders: validation 400", (await req("/api/known-senders", { method: "POST", body: { pattern: "??", kind: "ours", label: "x" } })).status === 400);
    check("known senders: duplicate 409", (await req("/api/known-senders", { method: "POST", body: { pattern: "203.0.113.0/24", kind: "ours", label: "x" } })).status === 409);
    const bulk = await req("/api/known-senders", { method: "POST", body: { senders: [{ pattern: "10.9.0.0/16", kind: "vendor", label: "Bulk A", source: "spf" }, { pattern: "203.0.113.0/24", kind: "ours", label: "dup" }, { pattern: "bad pattern", kind: "ours", label: "x" }] } });
    check("known senders: bulk add reports added and skipped", bulk.status === 200 && bulk.body.added.length === 1 && bulk.body.added[0].source === "spf" && bulk.body.skipped.length === 2);
    const ipsLabelled = await req("/api/ips");
    check("ips: sender label on rows", ipsLabelled.body.ips.find((r) => r.ip === "203.0.113.10").sender.label === "Our relay" && ipsLabelled.body.ips.find((r) => r.ip === "192.0.2.99").sender === null);
    check("summary: bySender", (await req("/api/summary")).body.bySender.ours.total === 42);
    const ksUpd = await req(`/api/known-senders/${ksAdd.body.sender.id}`, { method: "PUT", body: { label: "Our relay (edited)" } });
    check("known senders: update", ksUpd.status === 200 && ksUpd.body.sender.label === "Our relay (edited)");
    const spfMissing = await req("/api/known-senders/from-spf", { method: "POST", body: { domain: "no-such-domain-for-tests.invalid" } });
    check("known senders: from-spf on a domain without SPF", spfMissing.status === 200 && spfMissing.body.found === false && spfMissing.body.proposals.length === 0);
    check("known senders: from-spf validates the domain", (await req("/api/known-senders/from-spf", { method: "POST", body: { domain: "nope" } })).status === 400);
    check("known senders: delete", (await req(`/api/known-senders/${ksAdd.body.sender.id}`, { method: "DELETE" })).status === 200 && (await req("/api/known-senders")).body.senders.length === 1);

    // --- mailboxes (admin) ---
    check("mailboxes: empty list", (await req("/api/mailboxes")).body.mailboxes.length === 0);
    check("mailboxes: validation is 400", (await req("/api/mailboxes", { method: "POST", body: { tenantId: "t" } })).status === 400);
    const mbAdd = await req("/api/mailboxes", { method: "POST", body: { name: "Contoso", tenantId: "t-1", clientId: "c-1", clientSecret: "s-1", mailbox: "dmarc@contoso.test" } });
    check("mailboxes: add", mbAdd.status === 200 && mbAdd.body.mailbox.id && mbAdd.body.mailbox.hasSecret === true && !("clientSecret" in mbAdd.body.mailbox));
    const mbId = mbAdd.body.mailbox.id;
    check("mailboxes: duplicate is 409", (await req("/api/mailboxes", { method: "POST", body: { tenantId: "t-1", clientId: "c-1", clientSecret: "s-1", mailbox: "dmarc@contoso.test" } })).status === 409);
    const mbList = await req("/api/mailboxes");
    check("mailboxes: listed without secret", mbList.body.mailboxes.length === 1 && !JSON.stringify(mbList.body).includes("s-1"));
    const mbUpd = await req(`/api/mailboxes/${mbId}`, { method: "PUT", body: { name: "Contoso Ltd", folder: "DMARC" } });
    check("mailboxes: update", mbUpd.status === 200 && mbUpd.body.mailbox.name === "Contoso Ltd" && mbUpd.body.mailbox.folder === "DMARC" && mbUpd.body.mailbox.hasSecret);
    check("mailboxes: unknown id is 404", (await req("/api/mailboxes/nope", { method: "PUT", body: { name: "x" } })).status === 404);
    const mbTest = await req(`/api/mailboxes/${mbId}/test`, { method: "POST", body: {} });
    check("mailboxes: connection test reports the failure", mbTest.status === 200 && mbTest.body.ok === false && mbTest.body.stage === "token");
    const stNow = await req("/api/status");
    check("status: lists the mailbox with counts and last run", stNow.body.configured === true && stNow.body.mailboxes[0].id === mbId && stNow.body.mailboxes[0].counts === null);
    check("sync: unknown mailboxId is 404", (await req("/api/sync", { method: "POST", body: { mailboxId: "nope" } })).status === 404);
    const syncOne = await req("/api/sync", { method: "POST", body: { mailboxId: mbId } });
    await new Promise((r) => setTimeout(r, 400));
    const jobOne = await req(`/api/sync/${syncOne.body.jobId}`);
    check("sync: per-mailbox run fails on the unreachable tenant and is reported per mailbox", jobOne.body.status === "failed" && jobOne.body.mailboxes.length === 1 && jobOne.body.mailboxes[0].status === "failed");
    check("mailboxes: delete", (await req(`/api/mailboxes/${mbId}`, { method: "DELETE" })).status === 200 && (await req("/api/mailboxes")).body.mailboxes.length === 0);
    check("filter: mailbox param accepted", (await req("/api/summary?mailbox=env")).body.totals.messages === 53 && (await req("/api/summary?mailbox=other")).body.totals.messages === 0);

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
