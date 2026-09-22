/**
 * The ingest job: list new messages in the mailbox, unpack and parse each
 * attachment, store the reports. One job runs at a time; its progress is
 * exposed for the UI to poll, and finished runs are recorded in sync_runs.
 */
const dns = require("dns");
const { extractXmlDocuments, parseAggregateReport } = require("./dmarc-parser");
const { GraphError } = require("./graph");

const DAY = 86400;
const MAX_JOBS_KEPT = 20;
const PTR_CONCURRENCY = 8;
const PTR_BATCH = 500;

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function isoToSeconds(iso) {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : nowSeconds();
}

/** Errors that mean "nothing else will work either": stop the run instead of ploughing on. */
function isFatal(error) {
  if (!(error instanceof GraphError)) {
    return false;
  }
  return error.code === "not_configured" || error.code === "token" || error.status === 401 || error.status === 403
    || error.code === "folder_not_found" || error.code === "throttled";
}

function createSync({ db, graph, logger = console, backfillDays = 90, resolver } = {}) {
  const jobs = new Map();
  let running = null;
  let nextJobId = 1;
  let timer = null;
  let ptrInFlight = false;
  const reverse = resolver || (() => {
    const r = new dns.promises.Resolver({ timeout: 3000, tries: 1 });
    return (ip) => r.reverse(ip);
  })();

  function rememberJob(job) {
    jobs.set(job.id, job);
    while (jobs.size > MAX_JOBS_KEPT) {
      jobs.delete(jobs.keys().next().value);
    }
  }

  /** Where the next sync should start: a day before the newest message seen, or the backfill window. */
  function defaultSince() {
    const latest = db.latestMessageReceivedAt();
    if (latest) {
      return latest - DAY;
    }
    return nowSeconds() - backfillDays * DAY;
  }

  async function processMessage(job, message) {
    if (db.hasMessage(message.id)) {
      job.skipped += 1;
      return;
    }

    job.seen += 1;
    job.current = message.subject || message.id;

    // Graph failures here are transient (or fatal for the whole run); the message
    // is deliberately not recorded so the next run picks it up again.
    const attachments = await graph.getAttachments(message.id);

    let reportsFound = 0;
    const problems = [];
    for (const att of attachments) {
      let docs;
      try {
        docs = extractXmlDocuments(att.bytes, att.name);
      } catch (error) {
        problems.push(`${att.name || "attachment"}: ${error.message}`);
        continue;
      }

      for (const doc of docs) {
        let parsed;
        try {
          parsed = parseAggregateReport(doc.xml);
        } catch (error) {
          if (error.code === "not_a_report") {
            continue; // some other XML riding along (signatures, calendar items)
          }
          problems.push(`${doc.name}: ${error.message}`);
          continue;
        }

        const result = db.insertReport({
          messageId: message.id,
          attachmentName: doc.name || att.name,
          parsed,
          xml: doc.xml
        });
        reportsFound += 1;
        if (result.duplicate) {
          job.duplicates += 1;
        } else {
          job.added += 1;
        }
      }
    }

    let status = "no_report";
    if (reportsFound > 0) {
      status = "ingested";
    } else if (problems.length > 0) {
      status = "error";
      job.errors += 1;
    } else {
      job.noReport += 1;
    }

    db.recordMessage({
      graphId: message.id,
      internetMessageId: message.internetMessageId,
      receivedAt: isoToSeconds(message.receivedAt),
      subject: message.subject,
      fromAddr: message.from,
      status,
      error: problems.length ? problems.join("; ") : null
    });

    // Recording the message after a duplicate-only ingest keeps the row, but the
    // report itself belongs to whichever message delivered it first.
    if (problems.length && reportsFound > 0) {
      job.warnings += 1;
    }
  }

  async function execute(job) {
    const runId = db.startRun(job.trigger, job.since);
    job.runId = runId;

    try {
      const folderId = await graph.resolveFolderId();
      for await (const message of graph.listMessages({ folderId, since: job.since * 1000 })) {
        if (job.cancelled) {
          break;
        }
        try {
          await processMessage(job, message);
        } catch (error) {
          if (isFatal(error)) {
            throw error;
          }
          job.errors += 1;
          job.lastError = `${message.subject || message.id}: ${error.message}`;
          logger.warn?.(`sync: message ${message.id} failed: ${error.message}`);
        }
      }
      job.status = job.cancelled ? "cancelled" : "done";
    } catch (error) {
      job.status = "failed";
      job.error = error.message;
      logger.error?.(`sync: run failed: ${error.message}`);
    } finally {
      job.current = null;
      job.finishedAt = nowSeconds();
      running = null;
      db.finishRun(runId, {
        messagesSeen: job.seen,
        reportsAdded: job.added,
        duplicates: job.duplicates,
        errors: job.errors,
        errorText: job.error || job.lastError || null
      });
    }

    if (job.added > 0) {
      job.ptrPromise = lookupPtrs().catch((error) => logger.warn?.(`ptr lookups failed: ${error.message}`));
    }
  }

  /**
   * Starts a sync, or returns the one already running. `since` is unix seconds and
   * overrides the cursor (used for a deeper backfill).
   */
  function runSync({ trigger = "manual", since } = {}) {
    if (running) {
      return { job: running, alreadyRunning: true };
    }

    const job = {
      id: String(nextJobId++),
      status: "running",
      trigger,
      since: Number.isFinite(Number(since)) && Number(since) > 0 ? Math.floor(Number(since)) : defaultSince(),
      startedAt: nowSeconds(),
      finishedAt: null,
      seen: 0,
      skipped: 0,
      added: 0,
      duplicates: 0,
      noReport: 0,
      errors: 0,
      warnings: 0,
      current: null,
      lastError: null,
      error: null,
      runId: null,
      cancelled: false
    };
    running = job;
    rememberJob(job);
    job.promise = execute(job);
    return { job, alreadyRunning: false };
  }

  function getJob(id) {
    return jobs.get(String(id)) || null;
  }

  function currentJob() {
    return running;
  }

  /** Reverse-DNS for source IPs not yet looked up; results (or null) are cached in ip_info. */
  async function lookupPtrs() {
    if (ptrInFlight) {
      return 0;
    }
    ptrInFlight = true;
    let done = 0;
    try {
      const pending = db.ipsMissingPtr(PTR_BATCH);
      let index = 0;
      const worker = async () => {
        while (index < pending.length) {
          const ip = pending[index++];
          let ptr = null;
          try {
            const names = await reverse(ip);
            ptr = Array.isArray(names) && names.length ? names[0] : null;
          } catch {
            ptr = null;
          }
          db.setPtr(ip, ptr);
          done += 1;
        }
      };
      await Promise.all(Array.from({ length: Math.min(PTR_CONCURRENCY, pending.length) }, worker));
    } finally {
      ptrInFlight = false;
    }
    return done;
  }

  function startScheduler(intervalMinutes) {
    stopScheduler();
    const minutes = Number(intervalMinutes);
    if (!Number.isFinite(minutes) || minutes <= 0 || !graph.isConfigured()) {
      return false;
    }
    const kick = () => {
      const { alreadyRunning } = runSync({ trigger: "scheduled" });
      if (alreadyRunning) {
        logger.log?.("sync: scheduled run skipped, one is already running");
      }
    };
    timer = setInterval(kick, minutes * 60 * 1000);
    timer.unref?.();
    const first = setTimeout(kick, 10 * 1000);
    first.unref?.();
    return true;
  }

  function stopScheduler() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  return {
    runSync,
    getJob,
    currentJob,
    defaultSince,
    lookupPtrs,
    startScheduler,
    stopScheduler,
    isFatal
  };
}

/** The job fields the API exposes (drops the promise and internals). */
function publicJob(job) {
  if (!job) {
    return null;
  }
  const { promise, ptrPromise, cancelled, ...rest } = job;
  return rest;
}

module.exports = { createSync, publicJob };
