// 01-core.js: Element lookups, formatting helpers, the api() wrapper, theme, table builder.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

const statusEl = document.getElementById("status");
const themeToggleBtn = document.getElementById("theme-toggle");

const rangeSelect = document.getElementById("range-select");
const fromLabel = document.getElementById("from-label");
const toLabel = document.getElementById("to-label");
const fromDate = document.getElementById("from-date");
const toDate = document.getElementById("to-date");
const domainSelect = document.getElementById("domain-select");
const rangeLabel = document.getElementById("range-label");
const refreshBtn = document.getElementById("refresh-btn");
const exportBtn = document.getElementById("export-btn");
const searchInput = document.getElementById("search-input");
const hideForwards = document.getElementById("hide-forwards");

const statGrid = document.getElementById("stat-grid");
const chartWrap = document.getElementById("chart-wrap");
const chartSvg = document.getElementById("chart");
const chartTip = document.getElementById("chart-tip");
const chartEmpty = document.getElementById("chart-empty");
const chartForwardPct = document.getElementById("chart-forward-pct");
const retentionNote = document.getElementById("retention-note");

const ipsResults = document.getElementById("ips-results");
const ipsCount = document.getElementById("ips-count");
const failingOnly = document.getElementById("failing-only");
const ipDetail = document.getElementById("ip-detail");
const ipDetailTitle = document.getElementById("ip-detail-title");
const ipDetailSummary = document.getElementById("ip-detail-summary");
const ipDetailBody = document.getElementById("ip-detail-body");

const reportersResults = document.getElementById("reporters-results");
const reportersCount = document.getElementById("reporters-count");

const reportsResults = document.getElementById("reports-results");
const reportsCount = document.getElementById("reports-count");
const reporterFilter = document.getElementById("reporter-filter");
const reportsPrev = document.getElementById("reports-prev");
const reportsNext = document.getElementById("reports-next");
const reportsPageLabel = document.getElementById("reports-page-label");
const reportDetail = document.getElementById("report-detail");
const reportDetailTitle = document.getElementById("report-detail-title");
const reportDetailXml = document.getElementById("report-detail-xml");
const reportDetailSummary = document.getElementById("report-detail-summary");
const reportDetailBody = document.getElementById("report-detail-body");
const reportDetailExo = document.getElementById("report-detail-exo");
const ipDetailExo = document.getElementById("ip-detail-exo");

const syncState = document.getElementById("sync-state");
const graphConfig = document.getElementById("graph-config");
const syncNowBtn = document.getElementById("sync-now-btn");
const mailboxesResults = document.getElementById("mailboxes-results");
const addMailboxBtn = document.getElementById("add-mailbox-btn");
const mailboxForm = document.getElementById("mailbox-form");
const mailboxFormTitle = document.getElementById("mailbox-form-title");
const syncProgressList = document.getElementById("sync-progress-list");
const geoipRefreshBtn = document.getElementById("geoip-refresh-btn");
const mailboxSelect = document.getElementById("mailbox-select");
const mailboxLabel = document.getElementById("mailbox-label");
const backfillDate = document.getElementById("backfill-date");
const backfillBtn = document.getElementById("backfill-btn");
const syncProgress = document.getElementById("sync-progress");
const syncProgressText = document.getElementById("sync-progress-text");
const syncMessage = document.getElementById("sync-message");
const runsResults = document.getElementById("runs-results");
const errorsResults = document.getElementById("errors-results");

let csrfToken = null;
let currentUser = null;
let currentTheme = "light";
let reportsPage = 1;
let reportsPageSize = 50;
let syncPollTimer = null;
let lastDays = [];

const DAY = 86400;
const JOB_POLL_MS = 1500;

// --- generic helpers -------------------------------------------------------

/**
 * Copies text, falling back to a hidden textarea and execCommand when the
 * Clipboard API is unavailable (plain HTTP on a LAN address is not a secure
 * context, so navigator.clipboard is undefined there). Returns true on success.
 */
async function copyToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Permission denied or unfocused document: try the legacy path.
    }
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.top = "0";
  area.style.left = "0";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.focus();
  area.select();
  let ok;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  area.remove();
  return ok;
}

/** Selects an element's text so a plain Ctrl+C / Cmd+C copies it. */
function selectText(el) {
  const range = document.createRange();
  range.selectNodeContents(el);
  const selection = window.getSelection();
  selection.removeAllRanges();
  selection.addRange(range);
}

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.classList.toggle("is-error", isError);
}

function applyTheme(theme) {
  currentTheme = theme === "dark" ? "dark" : "light";
  document.body.classList.toggle("theme-dark", currentTheme === "dark");
  const label = themeToggleBtn.querySelector(".theme-label");
  if (label) {
    label.textContent = currentTheme === "dark" ? "Light Theme" : "Dark Theme";
  }
  localStorage.setItem("dmarc-theme", currentTheme);
  if (lastDays.length) {
    renderChart(lastDays);
  }
}

themeToggleBtn.addEventListener("click", () => applyTheme(currentTheme === "dark" ? "light" : "dark"));

// A one-time analysis (uploaded files, never stored) is served by the same analysis
// endpoints under /api/scratch/<id>; while one is open, report-reading paths are
// redirected there. Everything else (auth, status, settings) stays global.
let scratchId = null;
const SCRATCH_ROUTES = ["summary", "ips", "records", "reports", "reporters", "subdomains", "scorecard", "domains", "export", "weekly", "forensic", "tls", "policy"];

function apiPath(path) {
  if (!scratchId) return path;
  const m = String(path).match(/^\/api\/([a-z-]+)(\/|\?|$)/);
  return m && SCRATCH_ROUTES.includes(m[1]) ? `/api/scratch/${encodeURIComponent(scratchId)}${path.slice(4)}` : path;
}

// Requests started by one dashboard load are cancelled when the next one starts (a
// quick second filter change), so a slow answer to the old filter cannot land after
// the new one and leave a panel showing the wrong period.
let activeLoadSignal = null;

/** Runs an async handler and shows its error on the status line instead of leaving a rejection. */
function run(fn) {
  return Promise.resolve().then(fn).catch((error) => {
    if (error && error.name === "AbortError") return;
    setStatus(error.message, true);
  });
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  const res = await fetch(apiPath(path), { ...options, headers, signal: options.signal || activeLoadSignal || undefined });
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    // A 401 from the sign-in endpoints means "those credentials were wrong", not
    // "your session expired" - only the latter should bounce back to the login screen.
    const isAuthAttempt = path.startsWith("/api/auth/");

    if (!isAuthAttempt && (res.status === 401 || (res.status === 409 && data.setupRequired))) {
      csrfToken = null;
      currentUser = null;
      showAuthOverlay(data.setupRequired ? "setup" : "login");
      throw new Error(data.setupRequired ? "Setup required." : "Your session has expired. Sign in again.");
    }

    const error = new Error(data.error || `Request failed (${res.status})`);
    error.status = res.status;
    error.data = data;
    throw error;
  }

  return data;
}

const pad = (n) => String(n).padStart(2, "0");

// --- filtering a panel's table -------------------------------------------------------
//
// Each table panel has a search box in its head. The rows are already in the page, so
// filtering is a matter of hiding the ones whose text lacks any of the typed words;
// a re-render (new period, sort, refresh) re-applies the current text. The Reports
// panel is paginated on the server and uses the API instead (see 13-reports.js).

function attachTableFilter(inputId, containerId) {
  const input = document.getElementById(inputId);
  const container = document.getElementById(containerId);
  if (!input || !container) return;
  const count = document.createElement("span");
  count.className = "filter-count";
  count.hidden = true;
  input.insertAdjacentElement("afterend", count);
  const apply = () => {
    const words = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
    const rows = [...container.querySelectorAll("tbody > tr")].filter((tr) => !tr.classList.contains("expansion-row"));
    let shown = 0;
    for (const tr of rows) {
      const text = tr.textContent.toLowerCase();
      const hit = words.every((w) => text.includes(w));
      tr.hidden = !hit;
      if (hit) shown += 1;
      // A row's expanded detail follows it and should go wherever the row goes.
      const next = tr.nextElementSibling;
      if (next && next.classList.contains("expansion-row")) next.hidden = !hit;
    }
    input.classList.toggle("is-active", words.length > 0);
    count.hidden = !words.length;
    count.textContent = words.length ? `${shown} of ${rows.length}` : "";
  };
  input.addEventListener("input", apply);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      input.value = "";
      apply();
    }
  });
  new MutationObserver(() => { if (input.value.trim()) apply(); }).observe(container, { childList: true });
}

// --- printing one panel -----------------------------------------------------------
//
// "Print" on a panel marks it as the print target; the print stylesheet (dmarc.css)
// then hides everything else, shows every tab of the panel, and adds a heading
// with the app name, the filter in force and the date, so the sheet stands alone.

function printPanel(panelId, { title: customTitle = null, meta: customMeta = null } = {}) {
  const panel = document.getElementById(panelId);
  if (!panel) return;
  const heading = document.createElement("div");
  heading.className = "print-heading";
  const title = document.createElement("h1");
  title.textContent = customTitle || `DMARC Report Analyzer: ${(panel.querySelector(".panel-head h2") || {}).textContent || panelId}`;
  const meta = document.createElement("p");
  const bits = [rangeLabel ? rangeLabel.textContent : "", domainSelect.value ? `domain ${domainSelect.value}` : "all domains", mailboxSelect.value ? `mailbox ${mailboxSelect.options[mailboxSelect.selectedIndex].textContent}` : ""];
  // Panels that do not depend on the dashboard filter pass their own line.
  meta.textContent = customMeta || `${bits.filter(Boolean).join(" · ")} · printed ${formatTimestamp(Math.floor(Date.now() / 1000))}`;
  heading.append(title, meta);
  panel.prepend(heading);
  document.body.classList.add("print-focus");
  panel.classList.add("print-target");
  const cleanup = () => {
    document.body.classList.remove("print-focus");
    panel.classList.remove("print-target");
    heading.remove();
    window.removeEventListener("afterprint", cleanup);
  };
  window.addEventListener("afterprint", cleanup);
  window.print();
  // Browsers without afterprint (or a cancelled dialog) still get cleaned up, late
  // enough not to interfere with a print preview that is still being rendered.
  setTimeout(cleanup, 60000);
}

document.addEventListener("click", (e) => {
  const button = e.target.closest(".print-btn");
  if (button && button.dataset.print) printPanel(button.dataset.print);
});

// Times of events (syncs, alerts, sessions, forensic arrivals) are shown in a zone the
// user picks under Account: the browser's own, UTC, or any IANA zone. Report windows
// and chart days stay UTC calendar dates, because that is how receivers cut them.
let displayTimeZone = (() => {
  try {
    return localStorage.getItem("dmarc-tz") || "local";
  } catch {
    return "local";
  }
})();
const timeFormatters = new Map();

function timeFormatter(zone) {
  const key = zone || "local";
  if (!timeFormatters.has(key)) {
    const options = { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23" };
    if (zone && zone !== "local") options.timeZone = zone;
    timeFormatters.set(key, new Intl.DateTimeFormat("en-CA", options));
  }
  return timeFormatters.get(key);
}

function setDisplayTimeZone(zone) {
  displayTimeZone = zone || "local";
  try {
    localStorage.setItem("dmarc-tz", displayTimeZone);
  } catch { /* private mode */ }
}

/** Date and time of an event (unix seconds or ISO) in the chosen display zone. */
function formatTimestamp(ts) {
  if (!ts) {
    return "";
  }
  const d = new Date(typeof ts === "number" ? ts * 1000 : ts);
  let parts;
  try {
    parts = timeFormatter(displayTimeZone).formatToParts(d);
  } catch {
    parts = timeFormatter("local").formatToParts(d);
  }
  const get = (type) => (parts.find((p) => p.type === type) || {}).value || "";
  return `${get("year")}-${get("month")}-${get("day")} ${get("hour")}:${get("minute")}`;
}

/** UTC calendar date for report windows, which providers cut on UTC days. */
function formatUtcDate(seconds) {
  if (!seconds) {
    return "";
  }
  const d = new Date(seconds * 1000);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

function formatUtcDateTime(seconds) {
  if (!seconds) {
    return "";
  }
  const d = new Date(seconds * 1000);
  return `${formatUtcDate(seconds)} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}Z`;
}

/** A report window as "2026-09-18" or "2026-09-18 to 2026-09-20" (end is exclusive-ish, so step back a second). */
function formatWindow(begin, end) {
  const a = formatUtcDate(begin);
  const b = formatUtcDate(Math.max(begin, end - 1));
  return a === b ? a : `${a} to ${b}`;
}

function formatNumber(n) {
  return Number(n || 0).toLocaleString();
}

function formatPct(n) {
  return `${Number(n || 0).toFixed(1)}%`;
}

function textCell(text, className) {
  const td = document.createElement("td");
  td.textContent = text === null || text === undefined ? "" : String(text);
  if (className) {
    td.className = className;
  }
  return td;
}

/**
 * Renders a table. `onRowClick(data)` makes rows clickable; `expand(data)` instead
 * toggles a panel (the element it returns) directly under the clicked row.
 */
function buildTable(headers, rows, { emptyText = "Nothing to show.", onRowClick, expand } = {}) {
  if (!rows.length) {
    const p = document.createElement("p");
    p.className = "empty-state";
    p.textContent = emptyText;
    return p;
  }

  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  for (const h of headers) {
    const th = document.createElement("th");
    if (typeof h === "string") {
      th.textContent = h;
    } else {
      th.textContent = h.label;
      if (h.className) th.className = h.className;
    }
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const cell of row.cells) {
      tr.appendChild(cell instanceof HTMLElement ? cell : textCell(cell));
    }
    const activate = expand
      ? () => {
        const open = tr.nextElementSibling;
        const wasOpen = open && open.classList.contains("expansion-row") && open.dataset.owner === "1";
        for (const old of tbody.querySelectorAll("tr.expansion-row")) old.remove();
        for (const r of tbody.querySelectorAll("tr.is-expanded")) r.classList.remove("is-expanded");
        if (wasOpen) return;
        const panel = expand(row.data);
        if (!panel) return;
        const holder = document.createElement("tr");
        holder.className = "expansion-row";
        holder.dataset.owner = "1";
        const td = document.createElement("td");
        td.colSpan = headers.length;
        td.appendChild(panel);
        holder.appendChild(td);
        tr.after(holder);
        tr.classList.add("is-expanded");
      }
      : onRowClick ? () => onRowClick(row.data) : null;

    if (activate) {
      tr.className = "clickable";
      tr.tabIndex = 0;
      tr.addEventListener("click", activate);
      tr.addEventListener("keydown", (e) => {
        // Only for the row itself: Enter on a button inside the row is that button's.
        if ((e.key === "Enter" || e.key === " ") && e.target === tr) {
          e.preventDefault();
          activate();
        }
      });
    }
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  return table;
}

function resultBadge(passed, disposition) {
  const span = document.createElement("span");
  if (passed) {
    span.className = "pill pill-pass";
    span.textContent = "pass";
  } else {
    span.className = `pill pill-${disposition === "reject" ? "reject" : disposition === "quarantine" ? "quarantine" : "fail"}`;
    span.textContent = disposition === "none" ? "fail" : `fail, ${disposition}`;
  }
  return span;
}

function listCell(items, { mono = true, max = 3 } = {}) {
  const td = document.createElement("td");
  const shown = (items || []).slice(0, max);
  td.textContent = shown.join(", ") + (items && items.length > max ? ` +${items.length - max}` : "");
  if (mono) td.className = "mono";
  td.title = (items || []).join("\n");
  return td;
}
