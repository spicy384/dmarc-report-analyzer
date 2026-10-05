/**
 * Retention: when a number of months is set, reports older than that are rolled up
 * into daily totals and their records and stored XML removed. Totals and the chart
 * keep the history; sources, records and downloads only cover retained data.
 *
 * `months` may be a number or a function returning one, so the value chosen under
 * Settings (which overrides RETENTION_MONTHS) applies without a restart. The
 * daily timer always runs; a pass does nothing while retention is off.
 */
const DAY_MS = 86400 * 1000;
const MAX_MONTHS = 120;

/** Unix seconds for "months ago", on a calendar-month basis, at UTC midnight. */
function cutoffFor(months, now = Date.now()) {
  const d = new Date(now);
  const utc = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - months, d.getUTCDate()));
  return Math.floor(utc.getTime() / 1000);
}

/** A whole number of months between 0 (keep everything) and MAX_MONTHS, or null when not one. */
function parseMonths(value) {
  if (value === null || value === undefined || value === "") return null;
  const n = Number(value);
  return Number.isInteger(n) && n >= 0 && n <= MAX_MONTHS ? n : null;
}

function createRetention({ db, months = 0, logger = console } = {}) {
  let timer = null;
  let first = null;
  const currentMonths = () => {
    const n = Number(typeof months === "function" ? months() : months);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
  };
  const isEnabled = () => currentMonths() > 0;

  function purge({ now = Date.now() } = {}) {
    const m = currentMonths();
    if (!m) {
      return { skipped: true, reports: 0, records: 0, days: 0 };
    }
    const cutoff = cutoffFor(m, now);
    const result = db.purgeBefore(cutoff);
    if (result.reports) {
      logger.log?.(`retention: rolled up ${result.reports} report(s) / ${result.records} record(s) older than ${new Date(cutoff * 1000).toISOString().slice(0, 10)} into ${result.days} day total(s)`);
    }
    return { ...result, cutoff };
  }

  function describe() {
    const m = currentMonths();
    return { enabled: m > 0, months: m, cutoff: m ? cutoffFor(m) : null, ...db.retentionInfo() };
  }

  /** Schedules the first pass in 30 seconds and one a day after that. Returns whether retention is on right now. */
  function start() {
    stop();
    const run = () => {
      try {
        purge();
      } catch (error) {
        logger.error?.(`retention: ${error.message}`);
      }
    };
    first = setTimeout(run, 30 * 1000);
    first.unref?.();
    timer = setInterval(run, DAY_MS);
    timer.unref?.();
    return isEnabled();
  }

  function stop() {
    if (first) {
      clearTimeout(first);
      first = null;
    }
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  return {
    get enabled() { return isEnabled(); },
    purge,
    describe,
    start,
    stop,
    cutoffFor
  };
}

module.exports = { createRetention, cutoffFor, parseMonths, MAX_MONTHS };
