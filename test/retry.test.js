/** Sync retry after connection failures, and retention driven by a changeable setting. */
const { createChecker } = require("./helpers/assert");
const { openDatabase } = require("../db");
const { parseAggregateReport } = require("../dmarc-parser");
const { createSync, isTransient, normaliseRetryPolicy, retryDelay, RETRY_DEFAULTS } = require("../sync");
const { GraphError } = require("../graph");
const { createRetention, parseMonths } = require("../retention");

const { check, report } = createChecker("Sync retry and adjustable retention");
const quiet = { warn() {}, error() {}, log() {} };

// --- policy helpers ---------------------------------------------------------------------
check("isTransient: network codes and 502/503/504, not auth or 404", isTransient({ code: "network" }) && isTransient({ code: "ETIMEDOUT" }) && isTransient({ code: "ENOTFOUND" }) && isTransient({ status: 503 }) && !isTransient({ code: "token" }) && !isTransient({ status: 401 }) && !isTransient({ status: 404 }) && !isTransient(null));
check("normaliseRetryPolicy: defaults, clamping, backoff", JSON.stringify(normaliseRetryPolicy(null)) === JSON.stringify(RETRY_DEFAULTS) && normaliseRetryPolicy({ attempts: 99, delaySeconds: 0.2, backoff: "weird" }).attempts === 5 && normaliseRetryPolicy({ attempts: 99, delaySeconds: 0.2 }).delaySeconds === 1 && normaliseRetryPolicy({ attempts: 0, delaySeconds: 9999, backoff: "fixed" }).delaySeconds === 600 && normaliseRetryPolicy({ attempts: 1, backoff: "fixed" }).backoff === "fixed");
check("retryDelay: fixed and doubling", retryDelay({ delaySeconds: 10, backoff: "fixed" }, 3) === 10 && [1, 2, 3].map((n) => retryDelay({ delaySeconds: 10, backoff: "exponential" }, n)).join() === "10,20,40");

/** A mailbox client that fails `failures` times with `error` before working (and then lists nothing). */
function flakyClient(failures, makeError) {
  const state = { calls: 0 };
  return {
    state,
    config: { mailbox: "dmarc@example.com" },
    isConfigured: () => true,
    resolveFolderId: async () => {
      state.calls += 1;
      if (state.calls <= failures) throw makeError();
      return "inbox";
    },
    listMessages: async function* listMessages() { /* nothing new */ },
    getAttachments: async () => []
  };
}
const networkError = () => new GraphError("Could not reach the Microsoft sign-in service: fetch failed (ENOTFOUND)", { code: "network" });

async function run(sync) {
  const { job } = sync.runSync({ trigger: "test" });
  await job.promise;
  return job;
}

(async () => {
  // --- recovers on the second retry, waiting 10 s then 20 s ---
  const waits = [];
  const sleep = async (ms) => { waits.push(ms); };
  let db = openDatabase({ file: ":memory:" });
  let client = flakyClient(2, networkError);
  let job = await run(createSync({ db, graph: client, logger: quiet, retryPolicy: () => ({ attempts: 3, delaySeconds: 10, backoff: "exponential" }), sleep }));
  check("two connection failures, then success: the sync is done, not failed", job.status === "done" && job.mailboxes[0].status === "done" && job.mailboxes[0].retries === 2 && job.mailboxes[0].error === null && client.state.calls === 3, JSON.stringify({ status: job.status, box: job.mailboxes[0].status, retries: job.mailboxes[0].retries, calls: client.state.calls }));
  check("waited 10 s then 20 s", waits.join() === "10000,20000");
  check("each attempt is in the run history", db.runs(10).length === 3 && db.runs(10).filter((r) => r.error_text).length === 2);
  db.close();

  // --- gives up after the configured number of retries ---
  waits.length = 0;
  db = openDatabase({ file: ":memory:" });
  client = flakyClient(99, networkError);
  job = await run(createSync({ db, graph: client, logger: quiet, retryPolicy: () => ({ attempts: 2, delaySeconds: 5, backoff: "fixed" }), sleep }));
  check("still failing after 2 retries: failed, with the error kept", job.status === "failed" && job.mailboxes[0].retries === 2 && /Could not reach/.test(job.error) && client.state.calls === 3 && waits.join() === "5000,5000");
  db.close();

  // --- errors that would fail the same way are not retried ---
  waits.length = 0;
  db = openDatabase({ file: ":memory:" });
  client = flakyClient(99, () => new GraphError("AADSTS7000215: Invalid client secret provided.", { code: "token", status: 401 }));
  job = await run(createSync({ db, graph: client, logger: quiet, retryPolicy: () => ({ attempts: 3, delaySeconds: 1, backoff: "fixed" }), sleep }));
  check("a rejected secret is not retried", job.status === "failed" && job.mailboxes[0].retries === 0 && client.state.calls === 1 && waits.length === 0);
  db.close();

  // --- retries off, and the default when no policy is given ---
  db = openDatabase({ file: ":memory:" });
  client = flakyClient(1, networkError);
  job = await run(createSync({ db, graph: client, logger: quiet, retryPolicy: () => ({ attempts: 0, delaySeconds: 1 }), sleep }));
  check("attempts 0: fails at once", job.status === "failed" && client.state.calls === 1);
  client = flakyClient(1, networkError);
  job = await run(createSync({ db, graph: client, logger: quiet, sleep }));
  check("no policy given (older callers, tests): no retry", job.status === "failed" && client.state.calls === 1);
  db.close();

  // --- the policy is read per run, so a setting change applies to the next sync ---
  let policy = { attempts: 0, delaySeconds: 1, backoff: "fixed" };
  db = openDatabase({ file: ":memory:" });
  const sync = createSync({ db, graph: flakyClient(0, networkError), logger: quiet, retryPolicy: () => policy, sleep });
  await run(sync);
  policy = { attempts: 1, delaySeconds: 1, backoff: "fixed" };
  client = flakyClient(1, networkError);
  const sync2 = createSync({ db, graph: client, logger: quiet, retryPolicy: () => policy, sleep });
  job = await run(sync2);
  check("policy changed between runs is honoured", job.status === "done" && job.mailboxes[0].retries === 1);
  db.close();

  // --- retention follows a value that can change at runtime ---
  check("parseMonths: whole months 0..120 only", parseMonths("0") === 0 && parseMonths("12") === 12 && parseMonths(6) === 6 && parseMonths("") === null && parseMonths(null) === null && parseMonths("1.5") === null && parseMonths("-1") === null && parseMonths("121") === null && parseMonths("abc") === null);
  db = openDatabase({ file: ":memory:" });
  const DAY = 86400;
  const now = Date.parse("2026-10-01T00:00:00Z");
  const xml = (id, begin) => `<feedback><report_metadata><org_name>g</org_name><report_id>${id}</report_id><date_range><begin>${begin}</begin><end>${begin + DAY - 1}</end></date_range></report_metadata><policy_published><domain>example.com</domain><p>none</p></policy_published><record><row><source_ip>203.0.113.1</source_ip><count>5</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results></record></feedback>`;
  for (const [id, daysAgo] of [["old", 200], ["mid", 100], ["new", 5]]) {
    const x = xml(id, Math.floor(now / 1000) - daysAgo * DAY);
    db.insertReport({ messageId: id, parsed: parseAggregateReport(x), xml: x });
  }
  let months = 0;
  const retention = createRetention({ db, months: () => months, logger: quiet });
  check("off: enabled false, purge skipped, nothing touched", retention.enabled === false && retention.purge({ now }).skipped === true && retention.describe().months === 0 && db.reprocessableIds().length === 3);
  months = 6;
  const first = retention.purge({ now });
  check("setting changed to 6 months: the 200-day report is rolled up, without a restart", retention.enabled === true && first.reports === 1 && retention.describe().months === 6 && db.reprocessableIds().length === 2, JSON.stringify(first));
  months = 3;
  check("tightened to 3 months: the 100-day report follows", retention.purge({ now }).reports === 1 && db.reprocessableIds().length === 1);
  months = 0;
  check("switched off again: nothing more is removed, totals remain", retention.purge({ now }).skipped === true && retention.describe().enabled === false && retention.describe().purgedReports === 2 && db.summary({}).totals.messages === 15);
  check("start() schedules regardless and reports the current state", retention.start() === false && (retention.stop(), true));
  db.close();

  process.exit(report() ? 0 : 1);
})().catch((error) => { console.error(error); process.exit(1); });
