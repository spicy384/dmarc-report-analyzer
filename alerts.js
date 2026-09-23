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

module.exports = { evaluateAfterSync, SPIKE_DAYS, SPIKE_MIN_FAILED, SPIKE_FACTOR, NEW_SOURCE_QUIET_DAYS };
