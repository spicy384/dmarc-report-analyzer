/**
 * Retention: when RETENTION_MONTHS is set, reports older than that are rolled up
 * into daily totals and their records and stored XML removed. Totals and the chart
 * keep the history; sources, records and downloads only cover retained data.
 */
const DAY_MS = 86400 * 1000;

/** Unix seconds for "months ago", on a calendar-month basis, at UTC midnight. */
function cutoffFor(months, now = Date.now()) {
  const d = new Date(now);
  const utc = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - months, d.getUTCDate()));
  return Math.floor(utc.getTime() / 1000);
}

function createRetention({ db, months = 0, logger = console } = {}) {
  const enabled = Number.isFinite(Number(months)) && Number(months) > 0;
  let timer = null;

  function purge({ now = Date.now() } = {}) {
    if (!enabled) {
      return { skipped: true, reports: 0, records: 0, days: 0 };
    }
    const cutoff = cutoffFor(Number(months), now);
    const result = db.purgeBefore(cutoff);
    if (result.reports) {
      logger.log?.(`retention: rolled up ${result.reports} report(s) / ${result.records} record(s) older than ${new Date(cutoff * 1000).toISOString().slice(0, 10)} into ${result.days} day total(s)`);
    }
    return { ...result, cutoff };
  }

  function describe() {
    return { enabled, months: enabled ? Number(months) : 0, cutoff: enabled ? cutoffFor(Number(months)) : null, ...db.retentionInfo() };
  }

  function start() {
    stop();
    if (!enabled) {
      return false;
    }
    const run = () => {
      try {
        purge();
      } catch (error) {
        logger.error?.(`retention: ${error.message}`);
      }
    };
    const first = setTimeout(run, 30 * 1000);
    first.unref?.();
    timer = setInterval(run, DAY_MS);
    timer.unref?.();
    return true;
  }

  function stop() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  return { enabled, purge, describe, start, stop, cutoffFor };
}

module.exports = { createRetention, cutoffFor };
