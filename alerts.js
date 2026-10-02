/**
 * In-app alerts, evaluated after every sync that added reports:
 *   new_source   an IP failing DMARC that had never appeared before and is not a known sender
 *   spike        a source whose non-forward failures in the last 7 days are at least 3x the
 *                previous 7 days (and at least 20 messages)
 *   new_reporter the first report ever from a reporting organisation (informational)
 */
const DAY = 86400;
const SPIKE_DAYS = 7;
const SPIKE_MIN_FAILED = 20;
const SPIKE_FACTOR = 3;
const NEW_SOURCE_QUIET_DAYS = 90;

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function evaluateAfterSync({ db, addedReportIds, now = nowSeconds() } = {}) {
  const ids = (addedReportIds || []).filter((n) => Number.isInteger(n));
  const created = [];
  if (!ids.length) {
    return { created };
  }

  const newSourceIps = new Set();
  for (const src of db.newFailingSources(ids)) {
    if (db.senderFor(src.ip, src.ptr)) {
      continue; // labelled as ours/vendor/other: not news
    }
    if (db.alertExists("new_source", src.ip, { since: now - NEW_SOURCE_QUIET_DAYS * DAY })) {
      continue;
    }
    newSourceIps.add(src.ip);
    created.push(db.insertAlert({
      createdAt: now,
      type: "new_source",
      key: src.ip,
      severity: src.failed >= 10 ? "high" : "medium",
      title: `New failing source ${src.ip}${src.ptr ? ` (${src.ptr})` : ""}`,
      detail: { ip: src.ip, ptr: src.ptr, failed: src.failed, total: src.total, reporters: src.reporters, firstSeen: src.firstSeen, headerFroms: src.headerFroms }
    }));
  }

  for (const org of db.newReporters(ids)) {
    if (db.alertExists("new_reporter", org.orgName, { openOnly: false })) {
      continue;
    }
    created.push(db.insertAlert({
      createdAt: now,
      type: "new_reporter",
      key: org.orgName,
      severity: "info",
      title: `First reports from ${org.orgName}`,
      detail: { orgName: org.orgName, reports: org.reports, messages: org.messages }
    }));
  }

  for (const c of db.spikeCandidates({ now, days: SPIKE_DAYS, minFailed: SPIKE_MIN_FAILED, factor: SPIKE_FACTOR })) {
    if (newSourceIps.has(c.ip) || db.alertExists("new_source", c.ip, { openOnly: false, since: now - SPIKE_DAYS * DAY })) {
      continue; // the new-source alert already says it all
    }
    if (db.alertExists("spike", c.ip, { openOnly: false, since: now - SPIKE_DAYS * DAY })) {
      continue;
    }
    created.push(db.insertAlert({
      createdAt: now,
      type: "spike",
      key: c.ip,
      severity: "high",
      title: `Failures from ${c.ip}${c.ptr ? ` (${c.ptr})` : ""} jumped to ${c.recent} in ${SPIKE_DAYS} days (was ${c.previous})`,
      detail: { ip: c.ip, ptr: c.ptr, recent: c.recent, previous: c.previous, days: SPIKE_DAYS, sender: db.senderFor(c.ip, c.ptr) }
    }));
  }

  return { created };
}

function utcDate(seconds) {
  return Number.isFinite(seconds) ? new Date(seconds * 1000).toISOString().slice(0, 10) : "?";
}

/** One plain sentence of context for an alert, for webhooks and logs (the UI has its own). */
function describeAlert(a) {
  const d = (a && a.detail && typeof a.detail === "object") ? a.detail : {};
  switch (a && a.type) {
    case "new_source": {
      const bits = [`${d.failed} of ${d.total} messages failed`];
      if (d.headerFroms && d.headerFroms.length) bits.push(`claiming ${d.headerFroms.join(", ")}`);
      if (d.reporters && d.reporters.length) bits.push(`reported by ${d.reporters.join(", ")}`);
      return bits.join("; ");
    }
    case "spike":
      return `${d.recent} non-forward failures in the last ${d.days} days, ${d.previous} in the ${d.days} before${d.sender ? ` (known sender: ${d.sender.label})` : ""}`;
    case "new_reporter":
      return `${d.reports} report${d.reports === 1 ? "" : "s"} covering ${d.messages} messages`;
    case "dns_change":
      if (!d.found) return `Was: ${d.previous || "(empty)"}; unchanged since ${utcDate(d.previousSince)}`;
      if (!d.previousFound) return `Now: ${d.current}`;
      return `${d.summary ? `${d.summary}. ` : ""}Was: ${d.previous}; now: ${d.current}`;
    case "reporter_silent":
      return `Last report ${utcDate(d.lastSeen)}; it had sent ${d.reportsBeforeLast} reports in the 30 days before that${d.domains ? ` for ${d.domains} domain${d.domains === 1 ? "" : "s"}` : ""}`;
    case "ingest_stalled": {
      const boxes = (d.mailboxes || []).map((m) => `${m.name}: ${m.error ? `last sync failed (${m.error})` : m.lastRunAt ? `last sync ${utcDate(m.lastRunAt)}` : "never synced"}`);
      return `Last report stored ${utcDate(d.lastIngestedAt)}${boxes.length ? `. ${boxes.join("; ")}` : ""}`;
    }
    default:
      return typeof (a && a.detail) === "string" ? a.detail : "";
  }
}

module.exports = { evaluateAfterSync, describeAlert, SPIKE_DAYS, SPIKE_MIN_FAILED, SPIKE_FACTOR, NEW_SOURCE_QUIET_DAYS };
