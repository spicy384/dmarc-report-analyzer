/**
 * Monitoring that runs on a clock rather than on new data: the alerts a sync alone
 * cannot raise, because what went wrong is that nothing arrived or that DNS changed.
 *
 *   dns_change      a domain's DMARC, SPF or DKIM record changed or stopped resolving
 *                   since the last daily snapshot (the first snapshot is the baseline)
 *   reporter_silent a reporting service that used to send regularly has sent nothing
 *                   for REPORTER_SILENT_DAYS; it resolves itself when reports resume
 *   ingest_stalled  no report has been ingested for INGEST_STALL_HOURS although at
 *                   least one mailbox is enabled; also resolves itself
 *
 * Record history lives in dns_history, one row per distinct value with the window it
 * was observed in, so the Policy panel can show when a record last changed.
 */
const DAY = 86400;
const HOUR = 3600;

const DNS_SNAPSHOT_HOURS = 24;
const DNS_DOMAIN_LIMIT = 50;        // domains snapshotted per run, busiest first
const DNS_ACTIVE_DAYS = 90;         // only domains with reports this recent are tracked
const DKIM_SELECTOR_DAYS = 30;      // selectors seen signing in this window are checked
const REPORTER_SILENT_DAYS = 4;
const REPORTER_MIN_REPORTS = 7;     // reports in the 30 days before its last one to count as regular
const REPORTER_MAX_MEDIAN_GAP = 2;  // days between report days, at most, to count as regular
const INGEST_STALL_HOURS = 48;
const INGEST_MIN_REPORTS = 10;
const CHECK_EVERY_MS = 60 * 60 * 1000;
const FIRST_CHECK_MS = 60 * 1000;

const SETTING_SNAPSHOT_AT = "monitor_dns_snapshot_at";
const POLICY_RANK = { none: 0, quarantine: 1, reject: 2 };

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

/** Describes what a DMARC change means, so the alert title says more than "changed". */
function dmarcChangeSummary(previousValue, currentValue, parseDmarcTags) {
  if (!parseDmarcTags) return { text: "", weakened: false };
  const prev = previousValue ? parseDmarcTags(previousValue) : {};
  const cur = currentValue ? parseDmarcTags(currentValue) : {};
  const bits = [];
  let weakened = false;
  for (const tag of ["p", "sp", "pct", "adkim", "aspf"]) {
    const a = prev[tag];
    const b = cur[tag];
    if (a === b || (a === undefined && b === undefined)) continue;
    bits.push(`${tag}=${a === undefined ? "(unset)" : a} → ${b === undefined ? "(unset)" : b}`);
    if (tag === "p" && (POLICY_RANK[b] ?? -1) < (POLICY_RANK[a] ?? -1)) weakened = true;
    if (tag === "pct" && Number(b) < Number(a ?? 100)) weakened = true;
  }
  const ruaA = (prev.rua || []).join(",");
  const ruaB = (cur.rua || []).join(",");
  if (ruaA !== ruaB) bits.push(`rua ${ruaA || "(none)"} → ${ruaB || "(none)"}`);
  return { text: bits.join("; "), weakened };
}

const KIND_LABELS = { dmarc: "DMARC record", spf: "SPF record", dkim: "DKIM key", mta_sts: "MTA-STS record", mta_sts_policy: "MTA-STS policy", tlsrpt: "TLS-RPT record" };
const MODE_RANK = { none: 0, testing: 1, enforce: 2 };

/** What an MTA-STS policy change means: mode going from enforce towards none is a weakening. */
function mtaStsChangeSummary(previousValue, currentValue) {
  const mode = (text) => ((String(text || "").match(/^\s*mode\s*:\s*(\w+)/im) || [])[1] || "").toLowerCase();
  const a = mode(previousValue);
  const b = mode(currentValue);
  if (a === b) return { text: "", weakened: false };
  return { text: `mode ${a || "(unset)"} → ${b || "(unset)"}`, weakened: (MODE_RANK[b] ?? -1) < (MODE_RANK[a] ?? -1) };
}

function createMonitor({ db, dnsRecords, mailboxes = null, logger = console, now = nowSeconds, parseDmarcTags = null } = {}) {
  let timer = null;
  let running = null;
  const tags = parseDmarcTags || (dnsRecords && dnsRecords.parseDmarcTags) || null;

  /** Domains with reports in the active window, busiest first. */
  function trackedDomains(at) {
    return db.activeDomains({ since: at - DNS_ACTIVE_DAYS * DAY, limit: DNS_DOMAIN_LIMIT });
  }

  /**
   * Compares one observed record with the last stored value. The first observation
   * is stored silently; a change after that becomes an alert. Lookup errors (as
   * opposed to a clean "no such record") are skipped: a flaky resolver must never
   * read as "the record vanished".
   */
  function observe({ domain, kind, selector = "", found, value, at, describe }) {
    const outcome = db.observeDnsRecord({ domain, kind, selector, found, value, at });
    if (!outcome.changed || !outcome.previous) return null;
    const previous = outcome.previous;
    const label = kind === "dkim" ? `DKIM key ${selector}._domainkey.${domain}` : `${KIND_LABELS[kind] || `${kind} record`} for ${domain}`;
    let title;
    let severity = "medium";
    let summary = "";
    if (!found) {
      title = `${label} is gone`;
      severity = "high";
    } else if (!previous.found) {
      title = `${label} appeared`;
      severity = "info";
    } else {
      title = `${label} changed`;
      if (describe) {
        const d = describe(previous.value, value);
        summary = d.text;
        if (d.weakened) severity = "high";
      }
    }
    return db.insertAlert({
      createdAt: at,
      type: "dns_change",
      key: `${kind}:${selector ? `${selector}:` : ""}${domain}`,
      severity,
      title,
      detail: { domain, kind, selector: selector || null, previous: previous.value, previousFound: Boolean(previous.found), previousSince: previous.first_seen, current: value, found: Boolean(found), summary }
    });
  }

  /** Looks up every tracked record once and files what changed. */
  async function snapshotDns({ at = now(), refresh = true } = {}) {
    const created = [];
    const errors = [];
    const domains = trackedDomains(at);
    for (const { domain } of domains) {
      try {
        const dmarc = await dnsRecords.getDmarc(domain, { refresh });
        // getDmarc falls back to the organisational domain; what we track is the record this domain ends up with.
        const alert = observe({ domain, kind: "dmarc", found: Boolean(dmarc.found), value: dmarc.found ? dmarc.record : null, at, describe: (a, b) => dmarcChangeSummary(a, b, tags) });
        if (alert) created.push(alert);
      } catch (error) {
        errors.push(`${domain} DMARC: ${error.message}`);
      }
      try {
        const spf = await dnsRecords.getSpf(domain, { refresh });
        // getSpf folds resolver failures into `errors` and reports "not found"; only a clean miss counts as gone.
        if (!spf.found && spf.errors && spf.errors.length) {
          throw new Error(spf.errors[0].message || spf.errors[0].error || String(spf.errors[0]));
        }
        const alert = observe({ domain, kind: "spf", found: Boolean(spf.found), value: spf.found ? spf.record : null, at });
        if (alert) created.push(alert);
      } catch (error) {
        errors.push(`${domain} SPF: ${error.message}`);
      }
      // Transport security: the MTA-STS record, the policy file it points to, and TLS-RPT.
      if (typeof dnsRecords.getMtaSts === "function") {
        try {
          const sts = await dnsRecords.getMtaSts(domain, { refresh });
          const alert = observe({ domain, kind: "mta_sts", found: Boolean(sts.found), value: sts.found ? sts.record : null, at });
          if (alert) created.push(alert);
          // Only a fetched policy is evidence; a fetch failure says nothing about the file's content.
          if (sts.found && sts.policyText !== null) {
            const policyAlert = observe({ domain, kind: "mta_sts_policy", found: true, value: sts.policyText.trim(), at, describe: mtaStsChangeSummary });
            if (policyAlert) created.push(policyAlert);
          } else if (sts.found && sts.policyError) {
            errors.push(`${domain} MTA-STS policy: ${sts.policyError}`);
          }
        } catch (error) {
          errors.push(`${domain} MTA-STS: ${error.message}`);
        }
      }
      if (typeof dnsRecords.getTlsRpt === "function") {
        try {
          const rpt = await dnsRecords.getTlsRpt(domain, { refresh });
          const alert = observe({ domain, kind: "tlsrpt", found: Boolean(rpt.found), value: rpt.found ? rpt.record : null, at });
          if (alert) created.push(alert);
        } catch (error) {
          errors.push(`${domain} TLS-RPT: ${error.message}`);
        }
      }
      const selectors = db.dkimSelectors(domain, { from: at - DKIM_SELECTOR_DAYS * DAY })
        .filter((s) => s.selector && s.signingDomain && (s.signingDomain === domain || s.signingDomain.endsWith(`.${domain}`)));
      for (const s of selectors.slice(0, 20)) {
        const check = await dnsRecords.checkDkim(s.signingDomain, s.selector, { refresh }).catch((error) => ({ found: false, error: error.message }));
        if (check.error) {
          errors.push(`${s.selector}._domainkey.${s.signingDomain}: ${check.error}`);
          continue;
        }
        const alert = observe({ domain: s.signingDomain, kind: "dkim", selector: s.selector, found: Boolean(check.found), value: check.found ? check.record : null, at });
        if (alert) created.push(alert);
      }
    }
    db.setSetting(SETTING_SNAPSHOT_AT, String(at));
    return { created, errors, domains: domains.length };
  }

  /** Reporters that were regular and have gone quiet; resolves alerts for ones that resumed. */
  function checkReporters({ at = now() } = {}) {
    const created = [];
    const resolved = [];
    for (const rep of db.reporterCadence({ now: at })) {
      const silentFor = at - rep.lastSeen;
      const regular = rep.reportsBeforeLast >= REPORTER_MIN_REPORTS && rep.medianGapDays !== null && rep.medianGapDays <= REPORTER_MAX_MEDIAN_GAP;
      const silent = silentFor >= REPORTER_SILENT_DAYS * DAY;
      if (silent && regular) {
        if (db.alertExists("reporter_silent", rep.orgName, { openOnly: false, since: rep.lastSeen })) continue;
        const days = Math.floor(silentFor / DAY);
        created.push(db.insertAlert({
          createdAt: at,
          type: "reporter_silent",
          key: rep.orgName,
          severity: "medium",
          title: `No reports from ${rep.orgName} for ${days} day${days === 1 ? "" : "s"}`,
          detail: { orgName: rep.orgName, lastSeen: rep.lastSeen, days, reportsBeforeLast: rep.reportsBeforeLast, medianGapDays: rep.medianGapDays, domains: rep.domains }
        }));
      } else if (!silent) {
        const n = db.resolveAlerts("reporter_silent", rep.orgName, { note: "reports resumed" });
        if (n) resolved.push(rep.orgName);
      }
    }
    return { created, resolved };
  }

  /** Nothing ingested for too long while a mailbox is switched on. */
  function checkIngest({ at = now() } = {}) {
    const created = [];
    const resolved = [];
    const boxes = mailboxes ? mailboxes.list().filter((m) => m.enabled) : [];
    const last = db.lastIngest();
    if (!boxes.length || !last || last.reports < INGEST_MIN_REPORTS) {
      return { created, resolved };
    }
    const stalledFor = at - last.ingestedAt;
    if (stalledFor >= INGEST_STALL_HOURS * HOUR) {
      if (!db.alertExists("ingest_stalled", "all", { openOnly: false, since: last.ingestedAt })) {
        const runs = db.lastRunsByMailbox();
        const hours = Math.floor(stalledFor / HOUR);
        created.push(db.insertAlert({
          createdAt: at,
          type: "ingest_stalled",
          key: "all",
          severity: "high",
          title: `No reports ingested for ${hours} hours`,
          detail: {
            lastIngestedAt: last.ingestedAt,
            lastRangeEnd: last.rangeEnd,
            hours,
            mailboxes: boxes.map((m) => {
              const run = runs.find((r) => r.mailbox_id === m.id) || null;
              return { id: m.id, name: m.name || m.mailbox, lastRunAt: run ? run.finished_at || run.started_at : null, error: run ? run.error_text || null : null, errors: run ? run.errors : 0 };
            })
          }
        }));
      }
    } else if (db.resolveAlerts("ingest_stalled", "all", { note: "ingestion resumed" })) {
      resolved.push("all");
    }
    return { created, resolved };
  }

  /** The data-arrival checks: cheap, so they run after every sync and on the hourly tick. */
  function checkHealth({ at = now() } = {}) {
    const r = checkReporters({ at });
    const i = checkIngest({ at });
    return { created: [...r.created, ...i.created], resolved: [...r.resolved, ...i.resolved] };
  }

  function lastSnapshotAt() {
    const v = Number(db.getSetting(SETTING_SNAPSHOT_AT));
    return Number.isFinite(v) && v > 0 ? v : null;
  }

  function snapshotDue(at = now()) {
    const last = lastSnapshotAt();
    return !last || at - last >= DNS_SNAPSHOT_HOURS * HOUR;
  }

  /** Everything, once: the DNS snapshot and the health checks. One at a time. */
  async function runOnce({ at, force }) {
    const out = { created: [], resolved: [], errors: [], dnsSnapshot: false, domains: 0 };
    if (force || snapshotDue(at)) {
      const s = await snapshotDns({ at });
      out.created.push(...s.created);
      out.errors.push(...s.errors);
      out.dnsSnapshot = true;
      out.domains = s.domains;
    }
    const h = checkHealth({ at });
    out.created.push(...h.created);
    out.resolved.push(...h.resolved);
    return out;
  }

  function runAll({ at = now(), force = false } = {}) {
    if (running) return running;
    const p = runOnce({ at, force }).finally(() => {
      if (running === p) running = null;
    });
    running = p;
    return p;
  }

  function describe() {
    const at = now();
    return {
      lastDnsSnapshotAt: lastSnapshotAt(),
      nextDnsSnapshotAt: lastSnapshotAt() ? lastSnapshotAt() + DNS_SNAPSHOT_HOURS * HOUR : null,
      trackedDomains: trackedDomains(at).map((d) => d.domain),
      running: Boolean(running),
      thresholds: { dnsSnapshotHours: DNS_SNAPSHOT_HOURS, reporterSilentDays: REPORTER_SILENT_DAYS, reporterMinReports: REPORTER_MIN_REPORTS, ingestStallHours: INGEST_STALL_HOURS }
    };
  }

  function start({ onAlerts = null } = {}) {
    if (timer) return;
    const tick = () => {
      runAll().then((out) => {
        if (out.errors.length) logger.warn?.(`monitor: ${out.errors.length} lookup error(s): ${out.errors.slice(0, 3).join("; ")}`);
        if (out.created.length && onAlerts) onAlerts(out.created);
      }).catch((error) => logger.warn?.(`monitor: ${error.message}`));
    };
    const first = setTimeout(tick, FIRST_CHECK_MS);
    if (typeof first.unref === "function") first.unref();
    timer = setInterval(tick, CHECK_EVERY_MS);
    if (typeof timer.unref === "function") timer.unref();
  }

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  return { snapshotDns, checkReporters, checkIngest, checkHealth, runAll, describe, snapshotDue, lastSnapshotAt, start, stop };
}

module.exports = {
  createMonitor,
  dmarcChangeSummary,
  mtaStsChangeSummary,
  KIND_LABELS,
  DNS_SNAPSHOT_HOURS,
  REPORTER_SILENT_DAYS,
  REPORTER_MIN_REPORTS,
  REPORTER_MAX_MEDIAN_GAP,
  INGEST_STALL_HOURS,
  INGEST_MIN_REPORTS,
  DKIM_SELECTOR_DAYS
};
