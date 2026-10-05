// 17-settings.js: Dashboard / Settings views, backup and maintenance, notifications, active filters.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- dashboard / settings views ----------------------------------------------------
//
// One HTML page, two views: the dashboard (analysis panels) and Settings (mailboxes,
// known senders live on the dashboard since they annotate it; users, account). The
// view is part of the page link so a reload or a shared link lands on the same one.

const viewNav = document.getElementById("view-nav");
const VIEWS = { dashboard: document.getElementById("view-dashboard"), analyze: document.getElementById("view-analyze"), headers: document.getElementById("view-headers"), settings: document.getElementById("view-settings") };
let currentView = "dashboard";

async function setView(name, { scrollTo = null } = {}) {
  currentView = VIEWS[name] ? name : "dashboard";
  for (const [key, el] of Object.entries(VIEWS)) el.hidden = key !== currentView;
  for (const key of Object.keys(VIEWS)) document.getElementById(`nav-${key}`).classList.toggle("is-active", currentView === key);
  if (currentView === "settings" && currentUser) {
    accountPanel.hidden = false;
    renderAccountPanel();
    usersPanel.hidden = !isAdmin();
    maintenancePanel.hidden = !isAdmin();
    document.getElementById("audit-panel").hidden = !isAdmin();
    document.getElementById("notify-panel").hidden = !isAdmin();
    document.getElementById("monitor-panel").hidden = !isAdmin();
    document.getElementById("version-panel").hidden = !isAdmin();
    document.getElementById("sync-retry").hidden = !isAdmin();
    if (isAdmin()) loadSettingsBlocks();
    if (isAdmin()) {
      try { await refreshUsers(); } catch (error) { setStatus(error.message, true); }
      loadMaintenance();
      loadAudit();
      loadNotify();
      loadMonitor();
    }
  }
  writeHash();
  const target = scrollTo ? document.getElementById(scrollTo) : null;
  if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
  else window.scrollTo({ top: 0 });
}

document.getElementById("nav-dashboard").addEventListener("click", () => setView("dashboard"));
document.getElementById("nav-analyze").addEventListener("click", () => setView("analyze"));
document.getElementById("nav-headers").addEventListener("click", () => setView("headers"));
document.getElementById("nav-settings").addEventListener("click", () => setView("settings"));
accountBtn.addEventListener("click", () => setView("settings", { scrollTo: "account-panel" }));
usersBtn.addEventListener("click", () => setView("settings", { scrollTo: "users-panel" }));

// --- backup, restore, re-process --------------------------------------------------

const maintenancePanel = document.getElementById("maintenance-panel");
let reprocessTimer = null;

function describeReprocess(r) {
  if (!r) return "";
  if (r.running) return `Re-processing ${formatNumber(r.done)} of ${formatNumber(r.total)} reports... ${r.changed ? `${formatNumber(r.changed)} changed so far` : ""}`;
  if (r.finishedAt) return `Last run ${formatTimestamp(r.finishedAt)}: ${formatNumber(r.total)} reports, ${formatNumber(r.changed)} changed${r.errors ? `, ${formatNumber(r.errors)} errors (${r.lastError})` : ""}.`;
  return "";
}

async function loadMaintenance() {
  if (!isAdmin()) return;
  try {
    const st = await api("/api/maintenance/status");
    const status = document.getElementById("reprocess-status");
    status.textContent = describeReprocess(st.reprocess) || `${formatNumber(st.reprocessable)} reports have their XML stored.`;
    status.hidden = false;
    document.getElementById("reprocess-run").disabled = st.reprocess.running || st.syncRunning;
    document.getElementById("maintenance-badge").textContent = st.reprocess.running ? "Re-processing" : "";
    clearTimeout(reprocessTimer);
    if (st.reprocess.running) reprocessTimer = setTimeout(loadMaintenance, 1500);
    else if (reprocessTimer !== null) { reprocessTimer = null; loadAll(); }
  } catch (error) {
    setStatus(error.message, true);
  }
}

document.getElementById("backup-download").addEventListener("click", async () => {
  const btn = document.getElementById("backup-download");
  btn.disabled = true;
  try {
    const res = await fetch("/api/maintenance/backup", { headers: csrfToken ? { "X-CSRF-Token": csrfToken } : {} });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `Backup failed (${res.status})`);
    }
    const name = (res.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/)?.[1] || "dmarc-backup.tar.gz";
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    setStatus(`Backup downloaded (${formatNumber(Math.round(blob.size / 1024))} KB).`);
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("restore-run").addEventListener("click", async () => {
  const input = document.getElementById("restore-file");
  const file = input.files && input.files[0];
  const status = document.getElementById("restore-status");
  if (!file) {
    status.textContent = "Choose a backup file first.";
    status.hidden = false;
    return;
  }
  if (!confirm(`Restore from "${file.name}"?\n\nEverything currently in the database and the accounts and mailboxes will be replaced. This cannot be undone unless you have a backup of the current state.`)) return;
  const btn = document.getElementById("restore-run");
  btn.disabled = true;
  status.textContent = "Restoring...";
  status.hidden = false;
  try {
    const res = await fetch("/api/maintenance/restore", { method: "POST", headers: { "Content-Type": "application/gzip", ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}) }, body: file });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Restore failed (${res.status})`);
    status.textContent = `Restored the backup from ${data.manifest.createdAt}: ${formatNumber(data.database.reports)} reports, ${formatNumber(data.database.messages)} emails${data.settings.length ? `, ${data.settings.join(" and ")}` : ""}.`;
    input.value = "";
    if (data.signInAgain) {
      setStatus("Restored. Your account is not in the backup, so sign in again.", true);
      await refreshIdentity();
      return;
    }
    await loadDomains();
    await loadAll();
    setStatus("Restore complete.");
  } catch (error) {
    status.textContent = error.message;
    setStatus(error.message, true);
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("reprocess-run").addEventListener("click", async () => {
  if (!confirm("Re-parse every stored report with the current parser? This rewrites their records; totals only change if the parser now reads something differently.")) return;
  try {
    await api("/api/maintenance/reprocess", { method: "POST", body: "{}" });
    reprocessTimer = setTimeout(loadMaintenance, 500);
  } catch (error) {
    setStatus(error.message, true);
  }
});

// --- notifications ------------------------------------------------------------------

function describeNotifyResult(r) {
  if (!r) return "";
  return `${r.ok ? "Last delivery" : "Last attempt"} (${r.event}) ${formatTimestamp(r.at)}: ${r.detail}`;
}

async function loadNotify() {
  if (!isAdmin()) return;
  try {
    const s = await api("/api/notify");
    document.getElementById("nf-kind").value = s.kind;
    document.getElementById("nf-url").value = "";
    document.getElementById("nf-url").placeholder = s.configured ? `configured (${s.host}); leave blank to keep` : "https://...";
    document.getElementById("nf-app-url").value = s.appUrl || "";
    document.getElementById("nf-day").value = String(s.weeklyDay);
    document.getElementById("nf-hour").value = String(s.weeklyHour);
    document.getElementById("nf-alerts").checked = Boolean(s.alerts);
    document.getElementById("nf-weekly").checked = Boolean(s.weekly);
    document.getElementById("notify-badge").textContent = s.configured ? `${s.kind} via ${s.host}` : "off";
    const status = document.getElementById("nf-status");
    status.textContent = describeNotifyResult(s.lastResult) + (s.lastWeeklyAt ? ` Weekly summary last sent ${formatTimestamp(s.lastWeeklyAt)}.` : "");
    status.hidden = !status.textContent;
    document.getElementById("nf-test").disabled = !s.configured;
    document.getElementById("nf-weekly-now").disabled = !s.configured;
  } catch (error) {
    setStatus(error.message, true);
  }
}

// --- sync retry and retention settings ---------------------------------------------

const retryAttempts = document.getElementById("retry-attempts");
const retryDelayInput = document.getElementById("retry-delay");
const retryBackoff = document.getElementById("retry-backoff");
const retentionMonthsInput = document.getElementById("retention-months");
let savedRetention = null;
let retryDefaults = { attempts: 2, delaySeconds: 10, backoff: "exponential" };

/** Spells out what the chosen retry policy does, e.g. "waits 10 s, 20 s, then gives up". */
function renderRetryPreview() {
  const attempts = Number(retryAttempts.value);
  const delay = Math.max(1, Number(retryDelayInput.value) || 1);
  const preview = document.getElementById("retry-preview");
  retryDelayInput.disabled = attempts === 0;
  retryBackoff.disabled = attempts < 2;
  if (!attempts) {
    preview.textContent = "A mailbox that cannot be reached fails at once and waits for the next scheduled sync.";
    return;
  }
  const waits = [];
  for (let i = 1; i <= attempts; i += 1) waits.push(retryBackoff.value === "exponential" ? delay * 2 ** (i - 1) : delay);
  const total = waits.reduce((n, w) => n + w, 0);
  preview.textContent = `A mailbox that cannot be reached is tried again after ${waits.map((w) => `${w} s`).join(", then ")}; if it still fails, the sync reports the error (up to ${total >= 120 ? `${Math.round(total / 60)} min` : `${total} s`} of waiting per mailbox).`;
}

function renderRetentionStatus(r) {
  savedRetention = r;
  retentionMonthsInput.value = String(r.months);
  retentionMonthsInput.max = String(r.maxMonths || 120);
  const bits = [];
  if (r.enabled) {
    bits.push(`Keeping ${r.months} month${r.months === 1 ? "" : "s"} of detail: reports from before ${formatUtcDate(r.cutoff)} are rolled up at the daily pass.`);
  } else {
    bits.push("Keeping everything.");
  }
  if (r.purgedReports) bits.push(`${formatNumber(r.purgedReports)} reports rolled up so far into ${formatNumber(r.rolledUpDays)} daily totals.`);
  bits.push(r.source === "setting" ? "Set here." : r.source === "environment" ? `From RETENTION_MONTHS=${r.environmentMonths} in the environment; saving here overrides it.` : "");
  document.getElementById("retention-status").textContent = bits.filter(Boolean).join(" ");
  document.getElementById("retention-apply").disabled = !r.enabled;
}

async function loadSettingsBlocks() {
  if (!isAdmin()) return;
  try {
    const s = await api("/api/settings");
    retryDefaults = s.syncRetry.defaults || retryDefaults;
    retryAttempts.value = String(s.syncRetry.attempts);
    retryDelayInput.value = String(s.syncRetry.delaySeconds);
    retryBackoff.value = s.syncRetry.backoff;
    renderRetryPreview();
    renderRetentionStatus(s.retention);
  } catch (error) {
    setStatus(error.message, true);
  }
}

for (const el of [retryAttempts, retryDelayInput, retryBackoff]) el.addEventListener("input", renderRetryPreview);

async function saveRetryPolicy(policy) {
  try {
    const saved = await api("/api/settings/sync-retry", { method: "PUT", body: JSON.stringify(policy) });
    retryAttempts.value = String(saved.attempts);
    retryDelayInput.value = String(saved.delaySeconds);
    retryBackoff.value = saved.backoff;
    renderRetryPreview();
    setStatus(saved.attempts ? `Retry settings saved: ${saved.attempts} retr${saved.attempts === 1 ? "y" : "ies"} from the next sync.` : "Retries switched off.");
  } catch (error) {
    setStatus(error.message, true);
  }
}

document.getElementById("retry-save").addEventListener("click", () => saveRetryPolicy({ attempts: Number(retryAttempts.value), delaySeconds: Number(retryDelayInput.value), backoff: retryBackoff.value }));
document.getElementById("retry-reset").addEventListener("click", () => saveRetryPolicy(retryDefaults));

document.getElementById("retention-save").addEventListener("click", async () => {
  const months = Number(retentionMonthsInput.value);
  if (!Number.isInteger(months) || months < 0) {
    setStatus("Retention must be a whole number of months; 0 keeps everything.", true);
    return;
  }
  // Shortening (or switching on) retention deletes detail at the next pass: make that explicit.
  const before = savedRetention ? savedRetention.months : 0;
  const tighter = months > 0 && (before === 0 || months < before);
  if (tighter && !window.confirm(`Keep only ${months} month${months === 1 ? "" : "s"} of detail?\n\nAt the next daily pass (or with Apply now), the records, sources and stored XML of every older report are deleted for good. The totals and the chart keep the history. Take a backup first if you may want the detail back.`)) {
    retentionMonthsInput.value = String(before);
    return;
  }
  try {
    renderRetentionStatus(await api("/api/settings/retention", { method: "PUT", body: JSON.stringify({ months }) }));
    setStatus(months ? `Retention set to ${months} month${months === 1 ? "" : "s"}; it applies at the next daily pass, or use Apply now.` : "Retention switched off: everything is kept from now on.");
    loadSyncStatus().catch(() => {});
  } catch (error) {
    setStatus(error.message, true);
  }
});

document.getElementById("retention-apply").addEventListener("click", async () => {
  if (!savedRetention || !savedRetention.enabled) return;
  if (!window.confirm(`Roll up every report from before ${formatUtcDate(savedRetention.cutoff)} now?\n\nTheir records, sources and stored XML are deleted for good; only the daily totals remain. This cannot be undone.`)) return;
  const button = document.getElementById("retention-apply");
  button.disabled = true;
  try {
    const out = await api("/api/settings/retention/apply", { method: "POST", body: "{}" });
    renderRetentionStatus(out.retention);
    setStatus(out.result.reports ? `Rolled up ${formatNumber(out.result.reports)} reports (${formatNumber(out.result.records)} records) into daily totals.` : "Nothing older than the retention period; nothing was removed.");
    loadAll();
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    button.disabled = !(savedRetention && savedRetention.enabled);
  }
});

// --- version footer and update check ---------------------------------------------

function renderVersion(v) {
  const footer = document.getElementById("app-footer");
  const label = document.getElementById("app-version");
  const update = document.getElementById("app-update");
  const button = document.getElementById("app-update-check");
  footer.hidden = false;
  const build = [v.commit ? v.commit.slice(0, 7) : null, v.buildDate ? `built ${String(v.buildDate).slice(0, 10)}` : null].filter(Boolean).join(", ");
  label.textContent = `DMARC Report Analyzer v${v.version}${build ? ` (${build})` : ""}`;
  update.className = "app-update";
  if (!v.enabled) {
    update.textContent = "Update check off.";
  } else if (v.updateAvailable) {
    update.textContent = `Version ${v.latest} is available: pull the new image (docker compose pull && docker compose up -d).`;
    update.classList.add("is-update");
  } else if (v.error) {
    update.textContent = `Update check failed: ${v.error}.`;
  } else if (v.checkedAt) {
    update.textContent = `Up to date${v.latest ? ` (latest release ${v.latest})` : ""}; checked ${formatTimestamp(v.checkedAt)}.`;
  } else {
    update.textContent = "Update check pending.";
  }
  button.hidden = !isAdmin() || !v.enabled;

  // The Settings panel mirrors the footer and carries the switch.
  const box = document.getElementById("version-check-enabled");
  box.checked = Boolean(v.enabled);
  box.disabled = Boolean(v.lockedByEnvironment);
  document.getElementById("version-locked").hidden = !v.lockedByEnvironment;
  document.getElementById("version-badge").textContent = v.enabled ? (v.updateAvailable ? `${v.latest} available` : "checking daily") : "update check off";
  document.getElementById("version-current").textContent = `${label.textContent}. ${update.textContent}`;
  document.getElementById("version-check-now").disabled = !v.enabled;
}

async function checkForUpdateNow(button) {
  button.disabled = true;
  try {
    renderVersion(await api("/api/version/check", { method: "POST", body: "{}" }));
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    button.disabled = false;
  }
}

document.getElementById("app-update-check").addEventListener("click", (e) => checkForUpdateNow(e.currentTarget));
document.getElementById("version-check-now").addEventListener("click", (e) => checkForUpdateNow(e.currentTarget));

document.getElementById("version-check-enabled").addEventListener("change", async (e) => {
  const box = e.currentTarget;
  box.disabled = true;
  try {
    const v = await api("/api/version/settings", { method: "PUT", body: JSON.stringify({ enabled: box.checked }) });
    renderVersion(v);
    setStatus(v.enabled ? "Update check switched on." : "Update check switched off; the app no longer contacts the registry.");
  } catch (error) {
    setStatus(error.message, true);
    try {
      renderVersion(await api("/api/version"));
    } catch {
      // Could not even read the state back: undo the click and let the user try again.
      box.checked = !box.checked;
      box.disabled = false;
    }
  }
});

// --- monitoring (DNS drift, reporter silence, stalled ingestion) -----------------

async function loadMonitor() {
  if (!isAdmin()) return;
  try {
    const m = await api("/api/monitor");
    const t = m.thresholds;
    const facts = [
      m.lastDnsSnapshotAt
        ? `DNS records last snapshotted ${formatTimestamp(m.lastDnsSnapshotAt)}; the next snapshot is due around ${formatTimestamp(m.nextDnsSnapshotAt)}.`
        : "No DNS snapshot yet: the first one runs a minute after start-up and becomes the baseline.",
      m.trackedDomains.length
        ? `Tracking ${m.trackedDomains.length} domain${m.trackedDomains.length === 1 ? "" : "s"}: ${m.trackedDomains.join(", ")}.`
        : "No domains to track until reports arrive.",
      `A reporting service that sent at least ${t.reporterMinReports} reports in its last 30 days and then nothing for ${t.reporterSilentDays} days is flagged.`,
      `Nothing ingested for ${t.ingestStallHours} hours while a mailbox is enabled is flagged too.`
    ];
    document.getElementById("monitor-facts").replaceChildren(...facts.map((f) => {
      const li = document.createElement("li");
      li.textContent = f;
      return li;
    }));
    document.getElementById("monitor-badge").textContent = m.running ? "running" : m.lastDnsSnapshotAt ? "active" : "waiting for first snapshot";
    document.getElementById("monitor-run").disabled = Boolean(m.running);
  } catch (error) {
    setStatus(error.message, true);
  }
}

document.getElementById("monitor-run").addEventListener("click", async () => {
  const button = document.getElementById("monitor-run");
  const status = document.getElementById("monitor-status");
  button.disabled = true;
  status.hidden = false;
  status.textContent = "Looking up records and checking reporters...";
  try {
    const r = await api("/api/monitor/run", { method: "POST", body: "{}" });
    const bits = [`Checked ${r.domains} domain${r.domains === 1 ? "" : "s"}`, `${r.created.length} alert${r.created.length === 1 ? "" : "s"} created`, `${r.resolved.length} resolved`];
    if (r.errors.length) bits.push(`${r.errors.length} lookup error${r.errors.length === 1 ? "" : "s"}: ${r.errors.slice(0, 3).join("; ")}`);
    status.textContent = `${bits.join(", ")}.`;
    await Promise.all([loadMonitor(), loadAlerts()]);
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

document.getElementById("nf-save").addEventListener("click", async () => {
  const body = {
    kind: document.getElementById("nf-kind").value,
    appUrl: document.getElementById("nf-app-url").value,
    weeklyDay: Number(document.getElementById("nf-day").value),
    weeklyHour: Number(document.getElementById("nf-hour").value),
    alerts: document.getElementById("nf-alerts").checked,
    weekly: document.getElementById("nf-weekly").checked
  };
  const url = document.getElementById("nf-url").value.trim();
  if (url) body.url = url;
  try {
    await api("/api/notify", { method: "PUT", body: JSON.stringify(body) });
    setStatus("Notification settings saved.");
    await loadNotify();
  } catch (error) {
    setStatus(error.message, true);
  }
});

document.getElementById("nf-test").addEventListener("click", async () => {
  try {
    const r = await api("/api/notify/test", { method: "POST", body: "{}" });
    setStatus(r.ok ? "Test message delivered." : r.detail, !r.ok);
    await loadNotify();
  } catch (error) {
    setStatus(error.message, true);
  }
});

document.getElementById("nf-weekly-now").addEventListener("click", async () => {
  try {
    const r = await api("/api/notify/weekly", { method: "POST", body: "{}" });
    setStatus(r.ok ? "Weekly summary sent." : r.detail, !r.ok);
    await loadNotify();
  } catch (error) {
    setStatus(error.message, true);
  }
});

// --- active filters ---------------------------------------------------------------

/** Says which non-default filters shape the dashboard, so a stale search cannot mislead. */
function renderFilterChips() {
  const chips = [];
  if (domainSelect.value) chips.push(`domain ${domainSelect.value}`);
  if (mailboxSelect.value) chips.push(`mailbox ${mailboxNames.get(mailboxSelect.value) || mailboxSelect.value}`);
  if (searchInput.value.trim()) chips.push(`search "${searchInput.value.trim()}"`);
  if (hideForwards.checked) chips.push("likely forwards hidden");
  const box = document.getElementById("filter-chips");
  const list = document.getElementById("filter-chips-list");
  list.replaceChildren();
  for (const text of chips) {
    const chip = document.createElement("span");
    chip.className = "filter-chip";
    chip.textContent = text;
    list.appendChild(chip);
  }
  box.hidden = chips.length === 0;
}

document.getElementById("clear-filters-btn").addEventListener("click", () => {
  domainSelect.value = "";
  mailboxSelect.value = "";
  searchInput.value = "";
  hideForwards.checked = false;
  localStorage.setItem("dmarc-hide-forwards", "0");
  reportsPage = 1;
  loadAll();
});
