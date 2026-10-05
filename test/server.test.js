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
    check("status: walkthrough offered while no mailbox exists", status.body.setup && status.body.setup.needed === true && status.body.setup.dismissed === false);
    check("setup: dismiss sticks", (await req("/api/setup/dismiss", { method: "POST", body: {} })).status === 200 && (await req("/api/status")).body.setup.dismissed === true);

    // --- backup, restore, re-process, audit ---
    const bkRes = await fetch(`http://127.0.0.1:${APP_PORT}/api/maintenance/backup`, { headers: { Cookie: cookie, "X-CSRF-Token": csrf } });
    const bkBytes = Buffer.from(await bkRes.arrayBuffer());
    check("backup: downloads a gzip attachment", bkRes.status === 200 && bkRes.headers.get("content-type") === "application/gzip" && /dmarc-backup-\d{8}-\d{6}\.tar\.gz/.test(bkRes.headers.get("content-disposition") || "") && bkBytes[0] === 0x1f);
    const reportsBefore = (await req("/api/status")).body.stats.reports.reports;
    const badRestore = await fetch(`http://127.0.0.1:${APP_PORT}/api/maintenance/restore`, { method: "POST", headers: { Cookie: cookie, "X-CSRF-Token": csrf, "Content-Type": "application/gzip" }, body: Buffer.from("not a backup at all, just text") });
    check("restore: junk is refused", badRestore.status === 400 && (await req("/api/status")).body.stats.reports.reports === reportsBefore);
    const restoreRes = await fetch(`http://127.0.0.1:${APP_PORT}/api/maintenance/restore`, { method: "POST", headers: { Cookie: cookie, "X-CSRF-Token": csrf, "Content-Type": "application/gzip" }, body: bkBytes });
    const restoreBody = await restoreRes.json();
    check("restore: its own backup restores cleanly and keeps the session", restoreRes.status === 200 && restoreBody.ok && restoreBody.database.reports === reportsBefore && restoreBody.signInAgain === false && (await req("/api/status")).body.stats.reports.reports === reportsBefore, JSON.stringify(restoreBody).slice(0, 200));
    const rp = await req("/api/maintenance/reprocess", { method: "POST", body: {} });
    check("reprocess: starts", rp.status === 200 && rp.body.ok);
    let rpStatus = null;
    for (let i = 0; i < 40; i += 1) {
      rpStatus = (await req("/api/maintenance/status")).body;
      if (!rpStatus.reprocess.running) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    check("reprocess: finishes over every stored report with no errors", rpStatus && !rpStatus.reprocess.running && rpStatus.reprocess.total === reportsBefore && rpStatus.reprocess.errors === 0 && rpStatus.reprocess.done === reportsBefore, JSON.stringify(rpStatus && rpStatus.reprocess));
    check("reprocess: data unchanged by a re-parse with the same parser", (await req("/api/summary")).body.totals.messages === 53);
    const audit = await req("/api/audit");
    check("audit: backup, restore and reprocess were logged with the user", audit.status === 200 && ["backup.download", "backup.restore", "reports.reprocess"].every((a) => audit.body.entries.some((e) => e.action === a && e.username === "admin")), JSON.stringify(audit.body.entries.map((e) => e.action)));
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
    check("ips: every source carries a verdict", ips.body.ips.every((r) => r.verdict && r.verdict.code && r.verdict.headline));
    check("ips: the failing spoofer gets the spoof verdict", failing.body.ips[0].verdict.code === "spoof" || failing.body.ips[0].verdict.code === "unaligned", failing.body.ips[0].verdict.code);
    const withDays = await req("/api/ips?days=1");
    check("ips: days=1 attaches a per-day series", withDays.body.ips.every((r) => Array.isArray(r.days)) && withDays.body.ips.some((r) => r.days.length > 0 && r.days[0].day && r.days[0].total > 0));
    check("ips: no series without the flag", !("days" in ips.body.ips[0]));
    const ipDetail = await req("/api/ips/192.0.2.99");
    check("ips: detail", ipDetail.status === 200 && ipDetail.body.records.length === 1 && ipDetail.body.records[0].reasons.length === 2);
    check("ips: detail carries the verdict", ipDetail.body.verdict && typeof ipDetail.body.verdict.detail === "string");
    const card = await req("/api/scorecard");
    check("scorecard: one row per domain with status and issues", card.status === 200 && card.body.domains.length >= 1 && card.body.domains.every((d) => d.domain && d.status && Array.isArray(d.issues) && d.policy));
    const subs = await req("/api/subdomains");
    check("subdomains: rows carry relation and policy", subs.status === 200 && subs.body.subdomains.every((s) => ["parent", "subdomain", "other"].includes(s.relation)));
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

    // --- forensic reports ---
    check("forensic: empty list", (await req("/api/forensic")).body.total === 0 && (await req("/api/status")).body.forensicCount === 0);
    check("forensic: unknown id is 404", (await req("/api/forensic/999")).status === 404);

    // --- TLS reports and manual upload ---
    check("tls: empty list and count", (await req("/api/tls")).body.total === 0 && (await req("/api/status")).body.tlsCount === 0 && (await req("/api/tls/summary")).body.reports === 0);
    const upload = async (file, bytes) => {
      const res = await fetch(`http://127.0.0.1:${APP_PORT}/api/upload`, { method: "POST", headers: { Cookie: cookie, "X-CSRF-Token": csrf, "Content-Type": "application/octet-stream", "X-File-Name": encodeURIComponent(file) }, body: bytes });
      return { status: res.status, body: await res.json().catch(() => ({})) };
    };
    const reportsBeforeUpload = (await req("/api/status")).body.stats.reports.reports;
    const up1 = await upload("tls-report.json", fs.readFileSync(path.join(EX, "tls-report.json")));
    check("upload: TLS report stored and filed under the upload mailbox", up1.status === 200 && up1.body.tls.added === 1 && up1.body.status === "ingested" && (await req("/api/tls")).body.rows[0].mailboxId === "upload", JSON.stringify(up1.body));
    check("upload: tls list, detail, summary and JSON download", (await req("/api/tls/summary")).body.failed === 303 && (await req(`/api/tls/${(await req("/api/tls")).body.rows[0].id}`)).body.failures.length === 3 && (await req(`/api/tls/${(await req("/api/tls")).body.rows[0].id}/json`, { raw: true })).text.includes("Company-X"));
    const up2 = await upload("tls-report.json", fs.readFileSync(path.join(EX, "tls-report.json")));
    check("upload: the same file again is a duplicate", up2.status === 200 && up2.body.tls.added === 0 && up2.body.tls.duplicates === 1);
    const up3 = await upload("google.xml", Buffer.from(googleXml));
    check("upload: an aggregate report already in the database is a duplicate", up3.status === 200 && up3.body.aggregate.duplicates === 1 && up3.body.aggregate.added === 0);
    const up4 = await upload("forensic.eml", fs.readFileSync(path.join(EX, "forensic-report.eml")));
    check("upload: a forensic .eml is stored", up4.status === 200 && up4.body.forensic.added === 1 && (await req("/api/status")).body.forensicCount === 1, JSON.stringify(up4.body));
    const up5 = await upload("notes.txt", Buffer.from("just some text"));
    check("upload: junk is reported as a problem, HTTP 200, status error", up5.status === 200 && up5.body.status === "error" && up5.body.problems.length === 1);
    check("upload: empty body is 400", (await upload("x.xml", Buffer.alloc(0))).status === 400);
    const stAfter = await req("/api/status");
    check("upload: report count unchanged by duplicates; upload mailbox listed in counts; problem listed under errors", stAfter.body.stats.reports.reports === reportsBeforeUpload && stAfter.body.mailboxCounts.some((c) => c.id === "upload") && stAfter.body.errors.some((e) => /notes\.txt/.test(e.subject || "") || /not a DMARC/.test(e.error || "")), JSON.stringify(stAfter.body.errors).slice(0, 300));
    check("upload: audited", (await req("/api/audit?action=reports.upload")).body.entries.length >= 5);
    check("tls: mailbox filter", (await req("/api/tls?mailbox=upload")).body.total === 1 && (await req("/api/tls?mailbox=env")).body.total === 0);

    // --- one-time (scratch) analysis: same endpoints, separate in-memory database ---
    const scratchUpload = async (id, file, bytes) => {
      const res = await fetch(`http://127.0.0.1:${APP_PORT}/api/scratch${id ? `/${id}` : ""}/upload`, { method: "POST", headers: { Cookie: cookie, "X-CSRF-Token": csrf, "Content-Type": "application/octet-stream", "X-File-Name": encodeURIComponent(file) }, body: bytes });
      return { status: res.status, body: await res.json().catch(() => ({})) };
    };
    const liveReports = (await req("/api/status")).body.stats.reports.reports;
    const liveSummary = (await req("/api/summary?range=all")).body;
    const sc1 = await scratchUpload(null, "microsoft.xml", Buffer.from(microsoftXml));
    const scratchId = sc1.body.id;
    check("scratch: first upload creates an analysis", sc1.status === 200 && /^[0-9a-f]{24}$/.test(scratchId || "") && sc1.body.aggregate.added === 1 && sc1.body.analysis.reports === 1, JSON.stringify(sc1.body).slice(0, 300));
    check("scratch: the live store is untouched", (await req("/api/status")).body.stats.reports.reports === liveReports && JSON.stringify((await req("/api/summary?range=all")).body.totals) === JSON.stringify(liveSummary.totals));
    const scSummary = await req(`/api/scratch/${scratchId}/summary`);
    const scReports = await req(`/api/scratch/${scratchId}/reports`);
    check("scratch: analysis endpoints answer from the scratch database", scSummary.status === 200 && scSummary.body.totals.reports === 1 && scReports.body.total === 1 && scReports.body.rows[0].orgName !== "google.com" && scReports.body.rows[0].mailboxId === "upload", JSON.stringify(scSummary.body.totals));
    check("scratch: sources carry the live store's PTR and labels", (await req(`/api/scratch/${scratchId}/ips`)).body.ips.length > 0 && (await req(`/api/scratch/${scratchId}/domains`)).body.domains.length === 1);
    const sc2 = await scratchUpload(scratchId, "tls.json", fs.readFileSync(path.join(EX, "tls-report.json")));
    check("scratch: adding a file to the same analysis", sc2.status === 200 && sc2.body.id === scratchId && sc2.body.tls.added === 1 && (await req(`/api/scratch/${scratchId}/tls`)).body.total === 1);
    check("scratch: status lists the files", (await req(`/api/scratch/${scratchId}`)).body.files.length === 2 && (await req(`/api/scratch/${scratchId}`)).body.tls === 1);
    check("scratch: the XML of a scratch report downloads, and the live store has no such id collision issue", (await req(`/api/scratch/${scratchId}/reports/${scReports.body.rows[0].id}/xml`, { raw: true })).status === 200);
    check("scratch: unknown id is 404", (await req("/api/scratch/000000000000000000000000/summary")).status === 404 && (await req("/api/scratch/000000000000000000000000")).status === 404);
    check("scratch: delete, then gone", (await req(`/api/scratch/${scratchId}`, { method: "DELETE" })).status === 200 && (await req(`/api/scratch/${scratchId}/summary`)).status === 404);
    check("scratch: live TLS count unchanged by the scratch upload", (await req("/api/status")).body.tlsCount === 1);

    // --- version and the update-check switch (never enabled here: that would call the registry) ---
    const ver = (await req("/api/version")).body;
    check("version: reports the package version, check on by default and not locked", /^\d+\.\d+\.\d+$/.test(ver.version) && ver.enabled === true && ver.lockedByEnvironment === false && ver.checkedAt === null, JSON.stringify(ver));
    const verOff = await req("/api/version/settings", { method: "PUT", body: { enabled: false } });
    check("version: switching the check off sticks and shows in status", verOff.status === 200 && verOff.body.enabled === false && (await req("/api/status")).body.version.enabled === false && (await req("/api/version")).body.enabled === false);
    check("version: the switch is audited", (await req("/api/audit?action=version.update-check")).body.entries.some((e) => e.target === "off" && e.username === "admin"));

    // --- weekly summary ---
    const wk = await req("/api/weekly?end=2025-09-19");
    check("weekly: shape and totals", wk.status === 200 && wk.body.thisWeek.totals.messages === 53 && wk.body.lastWeek.totals.messages === 0 && wk.body.newSources.length === 4 && wk.body.topFailing.length === 2);
    check("weekly: plain text", /DMARC weekly summary/.test(wk.body.text) && /Messages: 53/.test(wk.body.text) && /New sources this week/.test(wk.body.text) && /192\.0\.2\.99 \(mail\.badhost\.test\)/.test(wk.body.text));
    check("weekly: bad end is 400", (await req("/api/weekly?end=whenever")).status === 400);
    check("weekly: domain filter", (await req("/api/weekly?end=2025-09-19&domain=nope.test")).body.thisWeek.totals.messages === 0);

    // --- policy readiness ---
    check("policy: domain required", (await req("/api/policy")).status === 400);
    const pol = await req("/api/policy?domain=no-such-domain-for-tests.invalid");
    check("policy: shape with no records and no reports", pol.status === 200 && pol.body.dmarc.found === false && pol.body.spf.found === false && Array.isArray(pol.body.dkim) && pol.body.reject.total === 0);
    const polEx = await req("/api/policy?domain=example.com");
    check("policy: reject breakdown from stored reports", polEx.status === 200 && polEx.body.reject.total === 53 && polEx.body.reject.spoofingBlocked.messages === 10 && polEx.body.reject.legitimateRejected.messages === 0 && polEx.body.reject.unlabelledFailingSources === 2);
    check("policy: dkim selectors checked", polEx.body.dkim.some((s) => s.selector === "selector1" && typeof s.found === "boolean"));
    check("policy: dmarc warnings is an array", Array.isArray(polEx.body.dmarc.warnings));

    // --- DNS lookup ---
    check("lookup: empty query is 400", (await req("/api/lookup")).status === 400);
    check("lookup: junk is 400", (await req("/api/lookup?q=not%20a%20name")).status === 400);
    const ld = await req("/api/lookup?q=no-such-domain-for-tests.invalid");
    check("lookup: domain shape", ld.status === 200 && ld.body.type === "domain" && ld.body.dmarc.found === false && ld.body.spf.found === false && ld.body.mx.found === false && Array.isArray(ld.body.addresses));
    const lip = await req("/api/lookup?q=192.0.2.99");
    check("lookup: ip seen in reports", lip.status === 200 && lip.body.type === "ip" && lip.body.ptr && Array.isArray(lip.body.ptr.names) && lip.body.seen && lip.body.seen.total > 0);
    const lunseen = await req("/api/lookup?q=192.0.2.250");
    check("lookup: ip never seen", lunseen.status === 200 && lunseen.body.seen === null && lunseen.body.known === null);

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
    const certPem = fs.readFileSync(path.join(__dirname, "helpers", "test-cert.pem"), "utf8");
    const keyPem = fs.readFileSync(path.join(__dirname, "helpers", "test-key.pem"), "utf8");
    const mbCert = await req("/api/mailboxes", { method: "POST", body: { name: "Cert", tenantId: "t-9", clientId: "c-9", authMethod: "certificate", certPem, keyPem, mailbox: "cert@contoso.test" } });
    check("mailboxes: add with a certificate", mbCert.status === 200 && mbCert.body.mailbox.authMethod === "certificate" && mbCert.body.mailbox.hasCertificate && mbCert.body.mailbox.certificate.thumbprint && !JSON.stringify(mbCert.body).includes("PRIVATE KEY"));
    check("mailboxes: bad certificate is 400", (await req("/api/mailboxes", { method: "POST", body: { tenantId: "t-9", clientId: "c-9", authMethod: "certificate", certPem: "nope", mailbox: "cert2@contoso.test" } })).status === 400);
    check("mailboxes: list never carries key material", !JSON.stringify((await req("/api/mailboxes")).body).includes("PRIVATE KEY"));
    await req(`/api/mailboxes/${mbCert.body.mailbox.id}`, { method: "DELETE" });
    const auditAll = (await req("/api/audit?limit=200")).body.entries;
    check("audit: mailbox changes are logged with target and detail", ["mailbox.add", "mailbox.update", "mailbox.remove"].every((a) => auditAll.some((e) => e.action === a && e.target && e.username === "admin")), JSON.stringify(auditAll.map((e) => e.action)));
    check("audit: mailbox.update names the fields that changed", auditAll.some((e) => e.action === "mailbox.update" && /changed .*name/.test(e.detail || "")));
    check("audit: known-sender changes are logged", auditAll.some((e) => e.action === "sender.add") && auditAll.some((e) => e.action === "sender.update" || e.action === "sender.remove"), JSON.stringify(auditAll.filter((e) => e.action.startsWith("sender.")).map((e) => e.action)));
    check("audit: filter by prefix", (await req("/api/audit?action=mailbox.")).body.entries.every((e) => e.action.startsWith("mailbox.")));

    // --- notifications ---
    const nf0 = await req("/api/notify");
    check("notify: off by default", nf0.status === 200 && nf0.body.configured === false && nf0.body.kind === "teams");
    check("notify: http URL refused", (await req("/api/notify", { method: "PUT", body: { url: "http://hook.test/x" } })).status === 400);
    const nf1 = await req("/api/notify", { method: "PUT", body: { url: "https://127.0.0.1:1/hook", kind: "slack", weeklyDay: 5, weeklyHour: 9 } });
    check("notify: saved, host shown, URL hidden, app link defaulted from the request", nf1.status === 200 && nf1.body.configured && nf1.body.host === "127.0.0.1:1" && !JSON.stringify(nf1.body).includes("/hook") && nf1.body.weeklyDayName === "Friday" && /^http:\/\/127\.0\.0\.1:\d+$/.test(nf1.body.appUrl), JSON.stringify(nf1.body));
    const nfTest = await req("/api/notify/test", { method: "POST", body: {} });
    check("notify: a test against an unreachable webhook reports the failure", nfTest.status === 200 && nfTest.body.ok === false && /Could not reach/.test(nfTest.body.detail));
    check("notify: settings changes are audited", (await req("/api/audit?action=notify.")).body.entries.some((e) => e.action === "notify.update" && /slack/.test(e.detail)));
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
