// 17-settings.js: Dashboard / Settings views, backup and maintenance, notifications, active filters.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- dashboard / settings views ----------------------------------------------------
//
// One HTML page, two views: the dashboard (analysis panels) and Settings (mailboxes,
// known senders live on the dashboard since they annotate it; users, account). The
// view is part of the page link so a reload or a shared link lands on the same one.

const viewNav = document.getElementById("view-nav");
const VIEWS = { dashboard: document.getElementById("view-dashboard"), analyze: document.getElementById("view-analyze"), settings: document.getElementById("view-settings") };
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
