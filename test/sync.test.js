/** End-to-end ingest against a mock Graph: paging, throttling, dedupe, errors, PTR lookups. */
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const { zipSync } = require("fflate");

const { createChecker } = require("./helpers/assert");
const { createMockGraph } = require("./helpers/mock-graph");
const { openDatabase } = require("../db");
const { createGraphClient } = require("../graph");
const { createSync, publicJob } = require("../sync");

const { check, report } = createChecker("Sync: Graph listing, ingest, retries, dedupe");
const EX = path.join(__dirname, "..", "examples");
const googleXml = fs.readFileSync(path.join(EX, "google-aggregate.xml"));
const microsoftXml = fs.readFileSync(path.join(EX, "microsoft-aggregate.xml"));
const bareXml = googleXml.toString().replace("<report_id>12345678901234567890</report_id>", "<report_id>bare-1</report_id>");
const brokenXml = "<feedback><record><row><source_ip>1.2.3.4</source_ip></row></record></feedback>";
const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);

const messages = [
  { id: "m1", subject: "Report domain: example.com Submitter: google.com", receivedDateTime: "2026-09-20T06:00:00Z", from: "noreply-dmarc-support@google.com",
    attachments: [{ name: "google.com!example.com!1758153600!1758239999.zip", contentType: "application/zip", bytes: zipSync({ "google.com!example.com!1758153600!1758239999.xml": new Uint8Array(googleXml) }) }] },
  { id: "m2", subject: "Report Domain: example.com Submitter: Enterprise Outlook", receivedDateTime: "2026-09-20T07:00:00Z", from: "dmarcreport@microsoft.com",
    attachments: [{ name: "enterprise.outlook.com!example.com!1758153600!1758240000.xml.gz", contentType: "application/gzip", bytes: zlib.gzipSync(microsoftXml) }, { name: "logo.png", contentType: "image/png", bytes: png }] },
  { id: "m3", subject: "Picture only", receivedDateTime: "2026-09-20T08:00:00Z", from: "someone@example.org",
    attachments: [{ name: "photo.png", contentType: "image/png", bytes: png }] },
  { id: "m4", subject: "Broken report", receivedDateTime: "2026-09-20T09:00:00Z", from: "reports@broken.test",
    attachments: [{ name: "broken.xml.gz", contentType: "application/gzip", bytes: zlib.gzipSync(Buffer.from(brokenXml)) }] },
  { id: "m5", subject: "Google again (duplicate)", receivedDateTime: "2026-09-21T06:00:00Z", from: "noreply-dmarc-support@google.com",
    attachments: [{ name: "again.zip", contentType: "application/octet-stream", bytes: zipSync({ "r.xml": new Uint8Array(googleXml) }) }] },
  { id: "m6", subject: "Bare xml on page two", receivedDateTime: "2026-09-21T07:00:00Z", from: "postmaster@small.test",
    attachments: [{ name: "report.xml", contentType: "text/xml", bytes: Buffer.from(bareXml) }, { name: "invite.ics", type: "#microsoft.graph.itemAttachment" }] },
  { id: "m7", subject: "Plain email, no attachments", receivedDateTime: "2026-09-21T08:00:00Z", from: "human@example.org", attachments: [] }
];

(async () => {
  const secondBox = [
    { id: "s1", subject: "Report from second mailbox", receivedDateTime: "2026-09-21T09:00:00Z", from: "noreply-dmarc-support@google.com",
      attachments: [{ name: "second.xml", contentType: "text/xml", bytes: Buffer.from(googleXml.toString().replace("<report_id>12345678901234567890</report_id>", "<report_id>second-1</report_id>").replace("<domain>example.com</domain>", "<domain>second.test</domain>")) }] }
  ];
  const mock = createMockGraph({ messages, mailboxes: { "second@example.com": secondBox } });
  const { loginBase, graphBase } = await mock.start();
  const db = openDatabase({ file: ":memory:" });

  const makeClient = (overrides = {}) => createGraphClient({
    tenantId: "tenant-id", clientId: "client-id", clientSecret: mock.secret, mailbox: mock.mailbox, folder: "Inbox",
    loginBase, graphBase, ...overrides
  }, { logger: { warn() {}, error() {}, log() {} } });

  const graph = makeClient();
  const resolver = async (ip) => {
    if (ip === "203.0.113.10") return ["mail-a.google.test"];
    throw new Error("ENOTFOUND");
  };
  const sync = createSync({ db, graph, backfillDays: 30, resolver, logger: { warn() {}, error() {}, log() {} } });

  // --- connection test ---------------------------------------------------------
  const conn = await graph.testConnection();
  check("testConnection ok", conn.ok === true && /Inbox/.test(conn.detail) && conn.totalItemCount === 7);
  const badSecret = await makeClient({ clientSecret: "wrong" }).testConnection();
  check("testConnection bad secret", badSecret.ok === false && badSecret.stage === "token" && /Invalid client secret/.test(badSecret.detail));
  const unconfigured = createGraphClient({ tenantId: "", clientId: "", clientSecret: "", mailbox: "" });
  check("describe lists missing settings", unconfigured.describe().missing.length === 4 && !unconfigured.isConfigured());
  check("folder lookup by name", await graph.resolveFolderId("DMARC Reports") === "folder-dmarc");
  let folderErr = null;
  try { await graph.resolveFolderId("Nope"); } catch (e) { folderErr = e; }
  check("missing folder is a clear error", folderErr && folderErr.code === "folder_not_found");

  // --- run 1: throttled once, one transient attachment failure --------------------
  mock.state.throttleOnce = true;
  mock.state.failAttachmentsOnce.add("m3");
  const first = sync.runSync({ trigger: "manual" });
  check("run starts", first.alreadyRunning === false && first.job.status === "running");
  check("second call while running returns the same job", sync.runSync().alreadyRunning === true && sync.runSync().job.id === first.job.id);
  check("default since is the backfill window on an empty db", Math.abs(first.job.since - (Date.now() / 1000 - 30 * 86400)) < 5);
  await first.job.promise;
  const j1 = publicJob(sync.getJob(first.job.id));

  check("run 1 done", j1.status === "done" && j1.finishedAt >= j1.startedAt);
  check("run 1 paged through all messages", j1.seen === 6 && j1.skipped === 0);
  check("run 1 added 3 reports", j1.added === 3, JSON.stringify(j1));
  check("run 1 saw 1 duplicate", j1.duplicates === 1);
  check("run 1 errors: broken xml + transient graph failure", j1.errors === 2 && /Picture only/.test(j1.lastError));
  check("run 1 no_report count is zero (m3 failed before it could be judged)", j1.noReport === 0);
  check("throttle was retried", mock.state.requests.filter((r) => /\/messages\?/.test(r.path)).length >= 3);
  const listing = mock.state.requests.find((r) => /\/messages\?/.test(r.path));
  check("listing filters on receivedDateTime only (hasAttachments in the filter triggers InefficientFilter)",
    /receivedDateTime%20ge%20/.test(listing.path) && !/hasAttachments/.test(decodeURIComponent(listing.path).replace(/\$select=[^&]*/, "")));
  check("attachment-less message is never fetched or recorded",
    !mock.state.requests.some((r) => /\/messages\/m7\//.test(r.path)) && !db.hasMessage("m7"));
  check("public job hides internals", !("promise" in j1) && !("ptrPromise" in j1));

  check("m3 was not recorded so it is retried", !db.hasMessage("m3"));
  check("m4 recorded as error", db.messagesWithErrors().some((m) => m.graph_id === "m4" && /report_metadata/.test(m.error)));
  check("m5 recorded as ingested despite being a duplicate", db.db.prepare("SELECT status FROM messages WHERE graph_id = 'm5'").get().status === "ingested");
  check("reports table has 3 rows", db.stats().reports.reports === 3);
  check("sync_runs row written", db.lastRun().reports_added === 3 && db.lastRun().errors === 2 && db.lastRun().trigger === "manual");

  await sync.getJob(first.job.id).ptrPromise;
  const ipRows = db.ips();
  check("ptr lookups cached", ipRows.find((r) => r.ip === "203.0.113.10").ptr === "mail-a.google.test" && ipRows.find((r) => r.ip === "192.0.2.99").ptr === null);
  check("no ips left to look up", db.ipsMissingPtr().length === 0);

  // --- run 2: everything already seen except m3 ---------------------------------
  const second = sync.runSync({ trigger: "scheduled" });
  check("cursor moves to a day before the newest message", second.job.since === Date.parse("2026-09-21T07:00:00Z") / 1000 - 86400);
  await second.job.promise;
  const j2 = publicJob(second.job);
  check("run 2 skips known messages", j2.skipped === 5 && j2.seen === 1);
  check("run 2 classifies m3 as no report", j2.noReport === 1 && j2.added === 0 && j2.errors === 0);
  check("run 2 nothing new", db.stats().reports.reports === 3 && db.hasMessage("m3"));

  // --- explicit backfill since ---------------------------------------------------
  const third = sync.runSync({ since: 1000 });
  check("since override honoured", third.job.since === 1000);
  await third.job.promise;
  check("run 3 all skipped", third.job.skipped === 6 && third.job.status === "done");

  // --- fatal: permission denied --------------------------------------------------
  mock.state.listStatus = 403;
  const fourth = sync.runSync();
  await fourth.job.promise;
  check("403 fails the run with guidance", fourth.job.status === "failed" && /Mail\.Read/.test(fourth.job.error));
  check("failed run recorded", db.lastRun().error_text && /Mail\.Read/.test(db.lastRun().error_text));
  check("runs kept in order", db.runs().length === 4 && db.runs()[0].id > db.runs()[1].id);

  // --- unconfigured client fails fast --------------------------------------------
  const syncUnconfigured = createSync({ db, graph: unconfigured, logger: { warn() {}, error() {}, log() {} } });
  const fifth = syncUnconfigured.runSync();
  await fifth.job.promise;
  check("unconfigured graph fails the run", fifth.job.status === "failed" && /GRAPH_TENANT_ID/.test(fifth.job.error));
  check("scheduler refuses to start unconfigured", syncUnconfigured.startScheduler(60) === false);
  check("scheduler starts when configured", sync.startScheduler(60) === true);
  sync.stopScheduler();

  // --- several mailboxes through the store -----------------------------------------
  const { createMailboxStore } = require("../mailboxes");
  const os = require("os");
  const storeDir = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-sync-store-"));
  const store = createMailboxStore({ dataDir: storeDir, loginBase, graphBase });
  const boxA = store.add({ name: "Primary", tenantId: "t", clientId: "c", clientSecret: mock.secret, mailbox: mock.mailbox });
  const boxB = store.add({ name: "Second", tenantId: "t", clientId: "c", clientSecret: mock.secret, mailbox: "second@example.com" });
  const boxC = store.add({ name: "Broken", tenantId: "t", clientId: "c", clientSecret: "wrong", mailbox: "third@example.com" });
  const db2 = openDatabase({ file: ":memory:" });
  const multi = createSync({ db: db2, mailboxes: store, backfillDays: 30, resolver, logger: { warn() {}, error() {}, log() {} } });

  const run = multi.runSync({ trigger: "manual" });
  check("job lists every enabled mailbox", run.job.mailboxes.length === 3 && run.job.mailboxes.map((b) => b.name).join(",") === "Primary,Second,Broken");
  await run.job.promise;
  const pj = publicJob(run.job);
  check("public job strips clients and report ids", pj.mailboxes.every((b) => !("client" in b)) && !("addedReportIds" in pj));
  const byName = Object.fromEntries(pj.mailboxes.map((b) => [b.name, b]));
  check("primary mailbox ingested", byName.Primary.status === "done" && byName.Primary.added === 3 && byName.Primary.seen === 6);
  check("second mailbox ingested its own report", byName.Second.status === "done" && byName.Second.added === 1 && byName.Second.seen === 1);
  check("broken mailbox failed without stopping the others", byName.Broken.status === "failed" && /Invalid client secret/.test(byName.Broken.error));
  check("job done with the failure noted", pj.status === "done" && /Broken/.test(pj.lastError) && pj.added === 4 && pj.seen === 7);
  check("reports carry their mailbox", db2.summary({ mailbox: boxB.id }).totals.reports === 1 && db2.summary({ mailbox: boxA.id }).totals.reports === 3 && db2.summary({ mailbox: boxC.id }).totals.reports === 0);
  check("reports list exposes mailboxId", db2.reports({ mailbox: boxB.id }).rows[0].mailboxId === boxB.id && db2.reports({ mailbox: boxB.id }).rows[0].domain === "second.test");
  check("one sync_runs row per mailbox", db2.runs().length === 3 && db2.runs().every((r) => r.mailbox_id) && db2.lastRunsByMailbox().length === 3);
  check("mailbox counts", db2.mailboxCounts().length === 2 && db2.mailboxCounts().find((c) => c.id === boxB.id).reports === 1);
  check("cursor is per mailbox", multi.defaultSince(boxB.id) === Date.parse("2026-09-21T09:00:00Z") / 1000 - 86400 && multi.defaultSince(boxA.id) === Date.parse("2026-09-21T07:00:00Z") / 1000 - 86400);

  const one = multi.runSync({ mailboxId: boxB.id });
  check("mailboxId limits the run", one.job.mailboxes.length === 1 && one.job.mailboxes[0].id === boxB.id);
  await one.job.promise;
  check("second run skips known messages", one.job.skipped === 1 && one.job.status === "done");

  store.update(boxC.id, { enabled: false });
  const again = multi.runSync();
  check("disabled mailbox is left out", again.job.mailboxes.length === 2);
  await again.job.promise;
  check("all mailboxes failing fails the job", (() => { store.update(boxA.id, { clientSecret: "bad" }); store.update(boxB.id, { clientSecret: "bad" }); return true; })());
  const allBad = multi.runSync();
  await allBad.job.promise;
  check("all mailboxes failing fails the job (result)", allBad.job.status === "failed" && /Primary/.test(allBad.job.error) && /Second/.test(allBad.job.error));

  const empty = createSync({ db: db2, mailboxes: createMailboxStore({ dataDir: fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-sync-empty-")) }), logger: { warn() {}, error() {}, log() {} } });
  const none = empty.runSync();
  await none.job.promise;
  check("no mailboxes fails with guidance and leaves a run row", none.job.status === "failed" && /No mailboxes/.test(none.job.error) && db2.lastRun().error_text.includes("No mailboxes"));
  check("scheduler refuses with no mailboxes", empty.startScheduler(60) === false);

  db2.close();
  fs.rmSync(storeDir, { recursive: true, force: true });

  db.close();
  await mock.stop();
  process.exit(report() ? 0 : 1);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
