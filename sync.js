/**
 * The ingest job: for every enabled mailbox, list new messages, unpack and parse
 * each attachment, store the reports. One job runs at a time; its progress is
 * exposed for the UI to poll, and each mailbox's run is recorded in sync_runs.
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

/** Errors that mean "nothing else in this mailbox will work either": stop it instead of ploughing on. */
function isFatal(error) {
  if (!(error instanceof GraphError)) {
    return false;
  }
  return error.code === "not_configured" || error.code === "token" || error.status === 401 || error.status === 403
    || error.code === "folder_not_found" || error.code === "throttled";
}

const COUNTERS = ["seen", "skipped", "added", "duplicates", "noReport", "errors", "warnings"];

/**
 * `mailboxes` is a mailbox store (enabledWithClients()). `graph` alone is still
 * accepted for a single client, which the older tests use.
 */
function createSync({ db, mailboxes, graph, logger = console, backfillDays = 90, resolver, onRunFinished } = {}) {
  const jobs = new Map();
  let running = null;
  let nextJobId = 1;
  let timer = null;
  let ptrInFlight = false;
  const reverse = resolver || (() => {
    const r = new dns.promises.Resolver({ timeout: 3000, tries: 1 });
    return (ip) => r.reverse(ip);
  })();

  function targets() {
    if (mailboxes) {
      return mailboxes.enabledWithClients();
    }
    if (graph) {
      return [{ id: "env", name: graph.config?.mailbox || "mailbox", mailbox: graph.config?.mailbox || null, client: graph }];
    }
    return [];
  }

  function anyConfigured() {
    return targets().some((t) => t.client.isConfigured());
  }

  function rememberJob(job) {
    jobs.set(job.id, job);
    while (jobs.size > MAX_JOBS_KEPT) {
      jobs.delete(jobs.keys().next().value);
    }
  }

  /** Where a mailbox's next sync should start: a day before its newest message, or the backfill window. */
  function defaultSince(mailboxId) {
    const latest = db.latestMessageReceivedAt(mailboxId);
    if (latest) {
      return latest - DAY;
    }
    return nowSeconds() - backfillDays * DAY;
  }

  function bump(job, box, counter, by = 1) {
    job[counter] += by;
    box[counter] += by;
  }

  async function processMessage(job, box, message) {
    if (db.hasMessage(message.id)) {
      bump(job, box, "skipped");
      return;
    }

    bump(job, box, "seen");
    job.current = `${box.name}: ${message.subject || message.id}`;

    // Graph failures here are transient (or fatal for the mailbox); the message
    // is deliberately not recorded so the next run picks it up again.
    const attachments = await box.client.getAttachments(message.id);

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
          mailboxId: box.id,
          attachmentName: doc.name || att.name,
          parsed,
          xml: doc.xml
        });
        reportsFound += 1;
        if (result.duplicate) {
          bump(job, box, "duplicates");
        } else {
          bump(job, box, "added");
          job.addedReportIds.push(result.reportId);
        }
      }
    }

    let status = "no_report";
    if (reportsFound > 0) {
      status = "ingested";
    } else if (problems.length > 0) {
      status = "error";
      bump(job, box, "errors");
    } else {
      bump(job, box, "noReport");
    }

    db.recordMessage({
      graphId: message.id,
      mailboxId: box.id,
      internetMessageId: message.internetMessageId,
      receivedAt: isoToSeconds(message.receivedAt),
      subject: message.subject,
      fromAddr: message.from,
      status,
      error: problems.length ? problems.join("; ") : null
    });

    if (problems.length && reportsFound > 0) {
      bump(job, box, "warnings");
    }
  }

  async function runMailbox(job, box) {
    box.status = "running";
    box.startedAt = nowSeconds();
    box.runId = db.startRun(job.trigger, box.since, box.id);

    try {
      const folderId = await box.client.resolveFolderId();
      for await (const message of box.client.listMessages({ folderId, since: box.since * 1000 })) {
        if (job.cancelled) {
          break;
        }
        try {
          await processMessage(job, box, message);
        } catch (error) {
          if (isFatal(error)) {
            throw error;
          }
          bump(job, box, "errors");
          box.lastError = `${message.subject || message.id}: ${error.message}`;
          job.lastError = `${box.name}: ${box.lastError}`;
          logger.warn?.(`sync: ${box.name}: message ${message.id} failed: ${error.message}`);
        }
      }
      box.status = job.cancelled ? "cancelled" : "done";
    } catch (error) {
      box.status = "failed";
      box.error = error.message;
      logger.error?.(`sync: ${box.name}: ${error.message}`);
    } finally {
      box.finishedAt = nowSeconds();
      db.finishRun(box.runId, {
        messagesSeen: box.seen,
        reportsAdded: box.added,
        duplicates: box.duplicates,
        errors: box.errors,
        errorText: box.error || box.lastError || null
      });
    }
  }

  async function execute(job) {
    try {
      if (!job.mailboxes.length) {
        throw new GraphError("No mailboxes are configured. Add one under Mailbox sync, or set GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET and DMARC_MAILBOX.", { code: "not_configured" });
      }
      for (const box of job.mailboxes) {
        if (job.cancelled) {
          break;
        }
        await runMailbox(job, box);
      }
      const failed = job.mailboxes.filter((b) => b.status === "failed");
      if (failed.length === job.mailboxes.length) {
        job.status = "failed";
        job.error = failed.map((b) => `${b.name}: ${b.error}`).join(" | ");
      } else {
        job.status = job.cancelled ? "cancelled" : "done";
        if (failed.length) {
          job.lastError = failed.map((b) => `${b.name}: ${b.error}`).join(" | ");
        }
      }
    } catch (error) {
      job.status = "failed";
      job.error = error.message;
      logger.error?.(`sync: run failed: ${error.message}`);
      if (!job.mailboxes.length) {
        // Still leave a trace in the run history so the UI can show why nothing happened.
        const runId = db.startRun(job.trigger, job.since, null);
        db.finishRun(runId, { errorText: error.message });
      }
    } finally {
      job.current = null;
      job.finishedAt = nowSeconds();
      running = null;
    }

    if (job.added > 0) {
      job.ptrPromise = lookupPtrs().catch((error) => logger.warn?.(`ptr lookups failed: ${error.message}`));
    }
    if (onRunFinished) {
      try {
        await onRunFinished(job);
      } catch (error) {
        logger.warn?.(`post-sync hook failed: ${error.message}`);
      }
    }
  }

  /**
   * Starts a sync, or returns the one already running. `since` is unix seconds and
   * overrides every mailbox's cursor (used for a deeper backfill). `mailboxId`
   * limits the run to one mailbox.
   */
  function runSync({ trigger = "manual", since, mailboxId } = {}) {
    if (running) {
      return { job: running, alreadyRunning: true };
    }

    const override = Number.isFinite(Number(since)) && Number(since) > 0 ? Math.floor(Number(since)) : null;
    const boxes = targets()
      .filter((t) => !mailboxId || t.id === mailboxId)
      .map((t) => ({
        id: t.id,
        name: t.name,
        mailbox: t.mailbox,
        client: t.client,
        status: "pending",
        since: override ?? defaultSince(t.id),
        startedAt: null,
        finishedAt: null,
        runId: null,
        lastError: null,
        error: null,
        ...Object.fromEntries(COUNTERS.map((c) => [c, 0]))
      }));

    const job = {
      id: String(nextJobId++),
      status: "running",
      trigger,
      since: override ?? (boxes.length ? Math.min(...boxes.map((b) => b.since)) : nowSeconds() - backfillDays * DAY),
      startedAt: nowSeconds(),
      finishedAt: null,
      ...Object.fromEntries(COUNTERS.map((c) => [c, 0])),
      current: null,
      lastError: null,
      error: null,
      mailboxes: boxes,
      addedReportIds: [],
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
    if (!Number.isFinite(minutes) || minutes <= 0 || !anyConfigured()) {
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
    anyConfigured,
    lookupPtrs,
    startScheduler,
    stopScheduler,
    isFatal
  };
}

/** The job fields the API exposes (drops the promise, clients and internals). */
function publicJob(job) {
  if (!job) {
    return null;
  }
  const { promise, ptrPromise, cancelled, addedReportIds, mailboxes, ...rest } = job;
  return {
    ...rest,
    mailboxes: (mailboxes || []).map(({ client, ...box }) => box)
  };
}

module.exports = { createSync, publicJob };
