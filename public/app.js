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

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  const res = await fetch(path, { ...options, headers });
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

/** Local date and time for mailbox and app events (unix seconds or ISO). */
function formatTimestamp(ts) {
  if (!ts) {
    return "";
  }
  const d = new Date(typeof ts === "number" ? ts * 1000 : ts);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
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
        if (e.key === "Enter") activate();
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

// --- period / domain filter ------------------------------------------------

function todayUtcStart() {
  const now = new Date();
  return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()) / 1000;
}

/** Returns { from, to } in unix seconds (to exclusive) plus a label; null bounds mean open-ended. */
function currentRange() {
  const preset = rangeSelect.value;
  if (preset === "all") {
    return { from: null, to: null, label: "All time" };
  }
  if (preset === "custom") {
    const from = fromDate.value ? Date.parse(`${fromDate.value}T00:00:00Z`) / 1000 : null;
    const to = toDate.value ? Date.parse(`${toDate.value}T00:00:00Z`) / 1000 + DAY : null;
    return { from, to, label: `${fromDate.value || "..."} to ${toDate.value || "..."}` };
  }
  const days = Number(preset);
  const to = todayUtcStart() + DAY;
  const from = to - days * DAY;
  return { from, to, label: `${formatUtcDate(from)} to ${formatUtcDate(to - 1)}` };
}

function filterQuery(extra = {}) {
  const { from, to } = currentRange();
  const params = new URLSearchParams();
  if (from !== null) params.set("from", String(from));
  if (to !== null) params.set("to", String(to));
  if (domainSelect.value) params.set("domain", domainSelect.value);
  if (mailboxSelect.value) params.set("mailbox", mailboxSelect.value);
  if (searchInput.value.trim()) params.set("q", searchInput.value.trim());
  if (hideForwards.checked) params.set("hideForwards", "1");
  for (const [k, v] of Object.entries(extra)) {
    if (v !== undefined && v !== null && v !== "") params.set(k, String(v));
  }
  const s = params.toString();
  return s ? `?${s}` : "";
}

function onRangeChanged() {
  const custom = rangeSelect.value === "custom";
  fromLabel.hidden = !custom;
  toLabel.hidden = !custom;
  if (custom && !fromDate.value) {
    fromDate.value = formatUtcDate(todayUtcStart() - 30 * DAY);
    toDate.value = formatUtcDate(todayUtcStart());
  }
  localStorage.setItem("dmarc-range", rangeSelect.value);
  reportsPage = 1;
  loadAll();
}

rangeSelect.addEventListener("change", onRangeChanged);
fromDate.addEventListener("change", () => { reportsPage = 1; loadAll(); });
toDate.addEventListener("change", () => { reportsPage = 1; loadAll(); });
domainSelect.addEventListener("change", () => { reportsPage = 1; loadAll(); });
mailboxSelect.addEventListener("change", () => { reportsPage = 1; loadAll(); });
refreshBtn.addEventListener("click", () => loadAll());

let searchTimer = null;
searchInput.addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { reportsPage = 1; loadAll(); }, 350);
});
searchInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    clearTimeout(searchTimer);
    reportsPage = 1;
    loadAll();
  }
});
hideForwards.addEventListener("change", () => {
  localStorage.setItem("dmarc-hide-forwards", hideForwards.checked ? "1" : "0");
  reportsPage = 1;
  loadAll();
});
failingOnly.addEventListener("change", () => loadIps());
reporterFilter.addEventListener("change", () => { reportsPage = 1; loadReports(); });

exportBtn.addEventListener("click", () => {
  const a = document.createElement("a");
  a.href = `/api/export/records.csv${filterQuery()}`;
  a.download = "dmarc-records.csv";
  document.body.appendChild(a);
  a.click();
  a.remove();
});

async function loadDomains() {
  const data = await api("/api/domains");
  const current = domainSelect.value;
  domainSelect.replaceChildren();
  const all = document.createElement("option");
  all.value = "";
  all.textContent = "All domains";
  domainSelect.appendChild(all);
  for (const d of data.domains || []) {
    const opt = document.createElement("option");
    opt.value = d.domain;
    opt.textContent = `${d.domain} (${formatNumber(d.messages)} msgs)`;
    domainSelect.appendChild(opt);
  }
  domainSelect.value = current;
  if (domainSelect.value !== current) {
    domainSelect.value = "";
  }
}

// --- overview --------------------------------------------------------------

function statTile(label, value, { sub = "", tone = "", small = false } = {}) {
  const div = document.createElement("div");
  div.className = `stat${tone ? " stat-" + tone : ""}${small ? " stat-small" : ""}`;
  const v = document.createElement("div");
  v.className = "stat-value";
  v.textContent = value;
  const l = document.createElement("div");
  l.className = "stat-label";
  l.textContent = label;
  div.append(v, l);
  if (sub) {
    const s = document.createElement("div");
    s.className = "stat-sub";
    s.textContent = sub;
    div.appendChild(s);
  }
  return div;
}

/** Failures split by who sent them: known-ours and vendors need SPF/DKIM fixed; the rest is spoofing. */
function senderTile(t) {
  const s = lastBySender || {};
  const yours = (s.ours?.failed || 0) + (s.vendor?.failed || 0);
  const notYours = (s.unknown?.failed || 0) + (s.other?.failed || 0);
  const unknownSources = s.unknown?.sources || 0;
  return statTile("Fails: yours / not yours", `${formatNumber(yours)} / ${formatNumber(notYours)}`, {
    sub: unknownSources ? `${formatNumber(unknownSources)} unlabelled source${unknownSources === 1 ? "" : "s"}` : "all sources labelled",
    tone: notYours > 0 ? "fail" : yours > 0 ? "quarantine" : "",
    small: true
  });
}

let lastBySender = null;

function renderStats(t) {
  statGrid.replaceChildren(
    statTile("Messages", formatNumber(t.messages), { sub: `${formatNumber(t.reports)} reports` }),
    statTile("DMARC pass", formatPct(t.passPct), { sub: `${formatNumber(t.passed)} messages`, tone: "pass" }),
    statTile("DMARC fail", formatPct(t.failPct), {
      sub: `${formatNumber(t.failed)} messages${t.likelyForwards ? `, ${formatNumber(t.likelyForwards)} likely forwards` : ""}`,
      tone: t.failed > 0 ? "fail" : ""
    }),
    statTile("Quarantined", formatNumber(t.quarantined), { tone: t.quarantined > 0 ? "quarantine" : "" }),
    statTile("Rejected", formatNumber(t.rejected), { tone: t.rejected > 0 ? "reject" : "" }),
    statTile("Failing sources", formatNumber(t.failingIps), { sub: `of ${formatNumber(t.sourceIps)} source IPs` }),
    senderTile(t),
    statTile("Reporters", formatNumber(t.reporters), { sub: t.domains > 1 ? `${t.domains} domains` : "" }),
    statTile("SPF / DKIM aligned", `${t.messages ? Math.round((t.spfPassed / t.messages) * 100) : 0}% / ${t.messages ? Math.round((t.dkimPassed / t.messages) * 100) : 0}%`, { tone: "small" })
  );
}

function cssVar(name) {
  return getComputedStyle(document.body).getPropertyValue(name).trim();
}

function dayKey(seconds) {
  return formatUtcDate(seconds);
}

/** Fills in the days with no reports so the bars line up with the calendar. */
function completeDays(days) {
  const byDay = new Map(days.map((d) => [d.day, d]));
  const { from, to } = currentRange();
  let start = from;
  let end = to;
  if (start === null || end === null) {
    if (!days.length) return [];
    start = start ?? Date.parse(`${days[0].day}T00:00:00Z`) / 1000;
    end = end ?? Date.parse(`${days[days.length - 1].day}T00:00:00Z`) / 1000 + DAY;
  }
  // Cap the number of empty days drawn so "all time" with a single report stays readable.
  const totalDays = Math.round((end - start) / DAY);
  if (totalDays > 400) {
    return days;
  }
  const out = [];
  for (let t = start; t < end; t += DAY) {
    const key = dayKey(t);
    out.push(byDay.get(key) || { day: key, total: 0, pass: 0, failForward: 0, failNone: 0, failQuarantine: 0, failReject: 0, fail: 0 });
  }
  return out;
}

function renderChart(days) {
  lastDays = days;
  const series = completeDays(days);
  const hasData = series.some((d) => d.total > 0);
  chartEmpty.hidden = hasData;
  chartSvg.replaceChildren();
  chartTip.hidden = true;
  if (!hasData) {
    chartSvg.setAttribute("height", "0");
    return;
  }

  const width = Math.max(320, chartWrap.clientWidth || 800);
  const height = 240;
  const margin = { top: 12, right: 12, bottom: 34, left: 52 };
  const innerW = width - margin.left - margin.right;
  const innerH = height - margin.top - margin.bottom;
  const max = Math.max(...series.map((d) => d.total), 1);

  chartSvg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  chartSvg.setAttribute("width", String(width));
  chartSvg.setAttribute("height", String(height));

  const ns = "http://www.w3.org/2000/svg";
  const make = (tag, attrs) => {
    const el = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
    return el;
  };

  const colors = {
    pass: cssVar("--chart-pass"),
    failForward: cssVar("--chart-forward"),
    failNone: cssVar("--chart-fail-none"),
    failQuarantine: cssVar("--chart-quarantine"),
    failReject: cssVar("--chart-reject"),
    grid: cssVar("--border"),
    text: cssVar("--text-muted")
  };

  // Gridlines with round tick values.
  const steps = 4;
  const rawStep = max / steps;
  const magnitude = Math.pow(10, Math.floor(Math.log10(rawStep)));
  const niceStep = [1, 2, 2.5, 5, 10].map((m) => m * magnitude).find((s) => s >= rawStep) || rawStep;
  const niceMax = Math.ceil(max / niceStep) * niceStep;
  const y = (v) => margin.top + innerH - (v / niceMax) * innerH;

  for (let v = 0; v <= niceMax + 1e-9; v += niceStep) {
    chartSvg.appendChild(make("line", { x1: margin.left, x2: width - margin.right, y1: y(v), y2: y(v), stroke: colors.grid, "stroke-width": 1 }));
    const label = make("text", { x: margin.left - 8, y: y(v) + 4, "text-anchor": "end", fill: colors.text, "font-size": 11 });
    label.textContent = formatNumber(Math.round(v));
    chartSvg.appendChild(label);
  }

  const n = series.length;
  const slot = innerW / n;
  const barW = Math.max(2, Math.min(28, slot * 0.72));
  const labelEvery = Math.max(1, Math.ceil(n / Math.max(1, Math.floor(innerW / 70))));

  series.forEach((d, i) => {
    const x = margin.left + i * slot + (slot - barW) / 2;
    let acc = 0;
    for (const [key, color] of [["pass", colors.pass], ["failForward", colors.failForward], ["failNone", colors.failNone], ["failQuarantine", colors.failQuarantine], ["failReject", colors.failReject]]) {
      const v = d[key] || 0;
      if (v <= 0) continue;
      const rect = make("rect", { x, y: y(acc + v), width: barW, height: Math.max(0, y(acc) - y(acc + v)), fill: color, rx: 1.5 });
      chartSvg.appendChild(rect);
      acc += v;
    }

    // An invisible full-height hit area per day makes hovering easy even for tiny bars.
    const hit = make("rect", { x: margin.left + i * slot, y: margin.top, width: slot, height: innerH, fill: "transparent" });
    hit.addEventListener("mouseenter", () => showTip(d, margin.left + i * slot + slot / 2));
    hit.addEventListener("mouseleave", () => { chartTip.hidden = true; });
    chartSvg.appendChild(hit);

    if (i % labelEvery === 0 || i === n - 1) {
      const label = make("text", { x: x + barW / 2, y: height - margin.bottom + 16, "text-anchor": "middle", fill: colors.text, "font-size": 11 });
      label.textContent = d.day.slice(5);
      chartSvg.appendChild(label);
    }
  });

  function showTip(d, cx) {
    const forwards = d.failForward || 0;
    const failed = forwards + (d.failNone || 0) + (d.failQuarantine || 0) + (d.failReject || 0);
    const fwdPct = failed ? Math.round((forwards / failed) * 100) : 0;
    chartTip.innerHTML = "";
    const title = document.createElement("strong");
    title.textContent = d.day;
    chartTip.appendChild(title);
    const lines = [
      ["Messages", formatNumber(d.total)],
      ["Pass", formatNumber(d.pass)],
      ["Fail", formatNumber(failed)],
      ["Likely forwards", failed ? `${formatNumber(forwards)} (${fwdPct}% of fails)` : "0"],
      ["Other, delivered", formatNumber(d.failNone)],
      ["Other, quarantined", formatNumber(d.failQuarantine)],
      ["Other, rejected", formatNumber(d.failReject)]
    ];
    for (const [label, v] of lines) {
      const line = document.createElement("div");
      line.textContent = `${label}: ${v}`;
      chartTip.appendChild(line);
    }
    chartTip.hidden = false;
    const wrapW = chartWrap.clientWidth;
    const tipW = chartTip.offsetWidth;
    const left = Math.min(Math.max(0, cx - tipW / 2), Math.max(0, wrapW - tipW));
    chartTip.style.left = `${left}px`;
    chartTip.style.top = "0px";
  }
}

let resizeTimer = null;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => lastDays.length && renderChart(lastDays), 150);
});

async function loadSummary() {
  const data = await api(`/api/summary${filterQuery()}`);
  lastBySender = data.bySender || null;
  renderStats(data.totals);
  renderChart(data.days || []);
  const t = data.totals;
  if (hideForwards.checked) {
    chartForwardPct.textContent = "Likely forwards hidden";
  } else if (t.failed > 0) {
    chartForwardPct.textContent = `Likely forwards: ${formatNumber(t.likelyForwards)} of ${formatNumber(t.failed)} fails (${Math.round((t.likelyForwards / t.failed) * 100)}%)`;
  } else {
    chartForwardPct.textContent = "";
  }
  return data;
}

// --- sources ---------------------------------------------------------------

function ipRow(r) {
  const dispositions = [];
  if (r.failNone) dispositions.push(`${formatNumber(r.failNone)} delivered`);
  if (r.quarantined) dispositions.push(`${formatNumber(r.quarantined)} quarantined`);
  if (r.rejected) dispositions.push(`${formatNumber(r.rejected)} rejected`);
  if (r.likelyForwards) dispositions.push(`${formatNumber(r.likelyForwards)} likely forwards`);

  const failCell = textCell(formatNumber(r.failed), r.failed > 0 ? "num is-fail" : "num");
  const senderCell = document.createElement("td");
  senderCell.className = "nowrap";
  senderCell.appendChild(senderPill(r.sender));
  if (canWrite()) {
    const labelBtn = document.createElement("button");
    labelBtn.type = "button";
    labelBtn.className = "link-btn small-link";
    labelBtn.textContent = r.sender ? "edit" : "label";
    labelBtn.title = r.sender ? "Edit this known sender" : "Mark this source as yours, a vendor, or other";
    labelBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      openSenderForm(r.sender ? { id: r.sender.id, pattern: r.sender.pattern, kind: r.sender.kind, label: r.sender.label } : { pattern: r.ip, kind: "ours", label: r.ptr ? r.ptr.split(".").slice(-3).join(".") : "" });
    });
    senderCell.append(" ", labelBtn);
  }
  return {
    data: r,
    cells: [
      textCell(r.ip, "mono"),
      textCell(r.ptr || "", "mono muted"),
      senderCell,
      textCell(formatNumber(r.total), "num"),
      failCell,
      textCell(formatPct(r.failPct), "num"),
      textCell(dispositions.join(", ") || (r.failed ? "" : "all passed"), "muted"),
      textCell(`${r.total ? Math.round((r.spfPassed / r.total) * 100) : 0}% / ${r.total ? Math.round((r.dkimPassed / r.total) * 100) : 0}%`, "num"),
      listCell(r.spfDomains.length ? r.spfDomains : r.envelopeFroms),
      listCell(r.dkimDomains),
      listCell(r.reporterNames, { mono: false }),
      textCell(formatUtcDate(Math.max(r.lastSeen - 1, r.firstSeen)), "nowrap")
    ]
  };
}

async function loadIps() {
  const data = await api(`/api/ips${filterQuery({ failing: failingOnly.checked ? 1 : 0, limit: 500 })}`);
  const rows = data.ips || [];
  ipsCount.textContent = `${rows.length} source${rows.length === 1 ? "" : "s"}`;
  ipsResults.replaceChildren(buildTable(
    ["Source IP", "Reverse DNS", "Sender", { label: "Messages", className: "num" }, { label: "Failed", className: "num" }, { label: "Fail %", className: "num" },
      "Failures by action", { label: "SPF / DKIM pass", className: "num" }, "SPF domain", "DKIM domain", "Reported by", "Last seen"],
    rows.map(ipRow),
    { emptyText: failingOnly.checked ? "No failing sources in this period." : "No sources in this period.", onRowClick: (r) => openIpDetail(r.ip) }
  ));
}

function recordRows(records, { showIp = false } = {}) {
  return records.map((rec) => {
    const auth = [];
    for (const d of rec.dkimResults || []) auth.push(`DKIM ${d.domain || "?"}${d.selector ? ` (${d.selector})` : ""}: ${d.result || "?"}`);
    for (const s of rec.spfResults || []) auth.push(`SPF ${s.domain || "?"}: ${s.result || "?"}`);
    const reasons = (rec.reasons || []).map((x) => x.comment ? `${x.type}: ${x.comment}` : x.type).join("; ");
    const cells = [
      textCell(formatWindow(rec.rangeBegin, rec.rangeEnd), "nowrap"),
      textCell(rec.orgName, "nowrap")
    ];
    if (showIp) {
      cells.push(textCell(rec.sourceIp, "mono"));
    }
    cells.push(
      textCell(formatNumber(rec.count), "num"),
      (() => {
        const td = document.createElement("td");
        td.className = "nowrap";
        td.appendChild(resultBadge(rec.passed, rec.disposition));
        if (rec.likelyForward) {
          const fwd = document.createElement("span");
          fwd.className = "pill pill-forward";
          fwd.textContent = "likely forward";
          fwd.title = "The reporter tagged this as forwarded or list mail, or a DKIM signature for the From domain was present but broken";
          td.append(" ", fwd);
        }
        return td;
      })(),
      textCell(`${rec.spfEval || "-"} / ${rec.dkimEval || "-"}`, "mono"),
      textCell(rec.headerFrom || "", "mono"),
      textCell(rec.envelopeFrom || "", "mono muted"),
      listCell(auth, { mono: false, max: 4 }),
      textCell(reasons, "muted")
    );
    return { data: rec, cells };
  });
}

async function openIpDetail(ip) {
  try {
    const d = await api(`/api/ips/${encodeURIComponent(ip)}${filterQuery()}`);
    ipDetailTitle.textContent = ip + (d.ptr ? `  (${d.ptr})` : "");
    ipDetailSummary.replaceChildren(
      kv("Messages", formatNumber(d.total)),
      kv("Failed", `${formatNumber(d.failed)} (${formatPct(d.failPct)})`),
      kv("Seen", `${formatUtcDate(d.firstSeen)} to ${formatUtcDate(Math.max(d.firstSeen, d.lastSeen - 1))}`),
      kv("Sender", d.sender ? `${d.sender.label} (${KIND_LABEL[d.sender.kind] || d.sender.kind}, ${d.sender.pattern})` : "unknown - not labelled"),
      kv("Reported by", d.reporterNames.join(", ")),
      kv("Header From", d.headerFroms.join(", ") || "-"),
      kv("Envelope From", d.envelopeFroms.join(", ") || "-"),
      kv("SPF domains", d.spfDomains.join(", ") || "-"),
      kv("DKIM domains", d.dkimDomains.join(", ") || "-")
    );
    const hint = document.createElement("p");
    hint.className = "bulk-hint";
    hint.textContent = "Click a report below for Exchange Online queries scoped to that report's window and this IP.";
    ipDetailExo.replaceChildren(hint);
    ipDetailBody.replaceChildren(buildTable(
      ["Window", "Reporter", { label: "Count", className: "num" }, "Result", "SPF / DKIM", "Header From", "Envelope From", "Auth results", "Reasons"],
      recordRows(d.records || []),
      { expand: (rec) => exoSearchBlock({ begin: rec.rangeBegin, end: rec.rangeEnd, ip: rec.sourceIp, domain: rec.domain, headerFroms: [rec.headerFrom] }) }
    ));
    ipDetail.hidden = false;
    ipDetail.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (error) {
    setStatus(error.message, true);
  }
}

document.getElementById("ip-detail-close").addEventListener("click", () => { ipDetail.hidden = true; });

function kv(label, value) {
  const div = document.createElement("div");
  div.className = "kv-item";
  const dt = document.createElement("span");
  dt.className = "kv-label";
  dt.textContent = label;
  const dd = document.createElement("span");
  dd.className = "kv-value";
  dd.textContent = value;
  div.append(dt, dd);
  return div;
}

// --- alerts ----------------------------------------------------------------

const alertsBanner = document.getElementById("alerts-banner");
const alertsTitle = document.getElementById("alerts-title");
const alertsList = document.getElementById("alerts-list");
const alertsAckAll = document.getElementById("alerts-ack-all");
const BASE_TITLE = document.title;

function describeAlert(a) {
  const d = a.detail || {};
  if (a.type === "new_source") {
    const bits = [`${formatNumber(d.failed)} of ${formatNumber(d.total)} messages failed`];
    if (d.headerFroms && d.headerFroms.length) bits.push(`claiming ${d.headerFroms.join(", ")}`);
    if (d.reporters && d.reporters.length) bits.push(`reported by ${d.reporters.join(", ")}`);
    if (d.firstSeen) bits.push(`first seen ${formatUtcDate(d.firstSeen)}`);
    return bits.join("; ");
  }
  if (a.type === "spike") {
    return `${formatNumber(d.recent)} non-forward failures in the last ${d.days} days, ${formatNumber(d.previous)} in the ${d.days} before${d.sender ? ` (known sender: ${d.sender.label})` : ""}`;
  }
  if (a.type === "new_reporter") {
    return `${formatNumber(d.reports)} report${d.reports === 1 ? "" : "s"} covering ${formatNumber(d.messages)} messages`;
  }
  return "";
}

function renderAlerts(alerts) {
  const open = alerts || [];
  document.title = open.length ? `(${open.length}) ${BASE_TITLE}` : BASE_TITLE;
  alertsBanner.hidden = open.length === 0;
  if (!open.length) {
    alertsList.replaceChildren();
    return;
  }
  const high = open.filter((a) => a.severity === "high").length;
  alertsTitle.textContent = `${open.length} alert${open.length === 1 ? "" : "s"} since the last acknowledgement${high ? ` (${high} high)` : ""}`;
  alertsList.replaceChildren(...open.map((a) => {
    const li = document.createElement("li");
    li.className = `alert alert-${a.severity}`;

    const sev = document.createElement("span");
    sev.className = `pill pill-sev-${a.severity}`;
    sev.textContent = a.type === "new_source" ? "new source" : a.type === "spike" ? "spike" : "new reporter";
    li.appendChild(sev);

    const body = document.createElement("div");
    body.className = "alert-body";
    const title = document.createElement("div");
    title.className = "alert-title";
    title.textContent = a.title;
    const desc = document.createElement("div");
    desc.className = "alert-desc";
    desc.textContent = `${describeAlert(a)} - ${formatTimestamp(a.created_at)}`;
    body.append(title, desc);
    li.appendChild(body);

    const actions = document.createElement("div");
    actions.className = "row-actions";
    if (a.type !== "new_reporter") {
      const show = document.createElement("button");
      show.type = "button";
      show.className = "secondary small";
      show.textContent = "Show";
      show.addEventListener("click", () => {
        searchInput.value = a.key;
        rangeSelect.value = "90";
        onRangeChanged();
        document.getElementById("sources-panel").scrollIntoView({ behavior: "smooth", block: "start" });
      });
      actions.appendChild(show);
    }
    if (canWrite()) {
      const ack = document.createElement("button");
      ack.type = "button";
      ack.className = "secondary small";
      ack.textContent = "Acknowledge";
      ack.addEventListener("click", async () => {
        try {
          await api(`/api/alerts/${encodeURIComponent(a.id)}/ack`, { method: "POST", body: "{}" });
          await loadAlerts();
        } catch (error) {
          setStatus(error.message, true);
        }
      });
      actions.appendChild(ack);
    }
    li.appendChild(actions);
    return li;
  }));
}

alertsAckAll.addEventListener("click", async () => {
  try {
    await api("/api/alerts/ack-all", { method: "POST", body: "{}" });
    await loadAlerts();
  } catch (error) {
    setStatus(error.message, true);
  }
});

async function loadAlerts() {
  const data = await api("/api/alerts?open=1");
  renderAlerts(data.alerts || []);
}

// --- known senders ---------------------------------------------------------

const sendersResults = document.getElementById("senders-results");
const sendersCount = document.getElementById("senders-count");
const senderForm = document.getElementById("sender-form");
const ksPattern = document.getElementById("ks-pattern");
const ksKind = document.getElementById("ks-kind");
const ksLabel = document.getElementById("ks-label");
const ksNote = document.getElementById("ks-note");
const ksSave = document.getElementById("ks-save");
const ksCancel = document.getElementById("ks-cancel");
const importSpfBtn = document.getElementById("import-spf-btn");
const spfImport = document.getElementById("spf-import");
const spfDomain = document.getElementById("spf-domain");
const spfSummary = document.getElementById("spf-summary");
const spfProposals = document.getElementById("spf-proposals");
const spfActions = document.getElementById("spf-actions");

const KIND_LABEL = { ours: "Ours", vendor: "Vendor", other: "Other" };
let editingSenderId = null;

function senderPill(sender) {
  const span = document.createElement("span");
  if (!sender) {
    span.className = "pill pill-unknown";
    span.textContent = "unknown";
    return span;
  }
  span.className = `pill pill-kind-${sender.kind}`;
  span.textContent = sender.label;
  span.title = `${KIND_LABEL[sender.kind] || sender.kind}: ${sender.pattern}`;
  return span;
}

function openSenderForm(prefill) {
  editingSenderId = prefill && prefill.id ? prefill.id : null;
  ksPattern.value = prefill ? prefill.pattern || "" : "";
  ksKind.value = prefill && prefill.kind ? prefill.kind : "ours";
  ksLabel.value = prefill ? prefill.label || "" : "";
  ksNote.value = prefill ? prefill.note || "" : "";
  ksSave.textContent = editingSenderId ? "Save" : "Add";
  ksCancel.hidden = !editingSenderId && !prefill;
  senderForm.scrollIntoView({ behavior: "smooth", block: "center" });
  (editingSenderId ? ksLabel : prefill ? ksLabel : ksPattern).focus();
}

function resetSenderForm() {
  editingSenderId = null;
  ksPattern.value = "";
  ksKind.value = "ours";
  ksLabel.value = "";
  ksNote.value = "";
  ksSave.textContent = "Add";
  ksCancel.hidden = true;
}

ksCancel.addEventListener("click", resetSenderForm);

ksSave.addEventListener("click", async () => {
  const body = { pattern: ksPattern.value, kind: ksKind.value, label: ksLabel.value, note: ksNote.value };
  try {
    if (editingSenderId) {
      await api(`/api/known-senders/${encodeURIComponent(editingSenderId)}`, { method: "PUT", body: JSON.stringify(body) });
      setStatus(`Updated ${body.label}.`);
    } else {
      await api("/api/known-senders", { method: "POST", body: JSON.stringify(body) });
      setStatus(`Added ${body.label}.`);
    }
    resetSenderForm();
    await loadKnownSenders();
    await Promise.all([loadSummary(), loadIps()]);
  } catch (error) {
    setStatus(error.message, true);
  }
});

async function loadKnownSenders() {
  const data = await api("/api/known-senders");
  const rows = data.senders || [];
  sendersCount.textContent = `${rows.length} entr${rows.length === 1 ? "y" : "ies"}`;
  sendersResults.replaceChildren(buildTable(
    ["Pattern", "Kind", "Label", "Note", "Added by", ""],
    rows.map((s) => {
      const actions = document.createElement("td");
      const wrap = document.createElement("div");
      wrap.className = "row-actions";
      if (canWrite()) {
        const edit = document.createElement("button");
        edit.className = "secondary small";
        edit.textContent = "Edit";
        edit.addEventListener("click", () => openSenderForm(s));
        wrap.appendChild(edit);
      }
      if (isAdmin()) {
        const del = document.createElement("button");
        del.className = "ghost-danger small";
        del.textContent = "Delete";
        del.addEventListener("click", async () => {
          if (!confirm(`Remove "${s.label}" (${s.pattern})?`)) return;
          try {
            await api(`/api/known-senders/${encodeURIComponent(s.id)}`, { method: "DELETE" });
            await loadKnownSenders();
            await Promise.all([loadSummary(), loadIps()]);
          } catch (error) {
            setStatus(error.message, true);
          }
        });
        wrap.appendChild(del);
      }
      actions.appendChild(wrap);
      return {
        data: s,
        cells: [
          textCell(s.pattern, "mono nowrap"),
          textCell(KIND_LABEL[s.kind] || s.kind),
          textCell(s.label),
          textCell(s.note || "", "muted"),
          textCell(`${s.created_by || (s.source === "spf" ? "SPF import" : "")}${s.source === "spf" ? " (SPF)" : ""}`, "muted nowrap"),
          actions
        ]
      };
    }),
    { emptyText: "No known senders yet. Add your own mail servers above, or import them from your SPF record." }
  ));
}

// --- SPF import -------------------------------------------------------------

importSpfBtn.addEventListener("click", () => {
  spfImport.hidden = !spfImport.hidden;
  if (!spfImport.hidden) {
    if (!spfDomain.value) {
      spfDomain.value = domainSelect.value || (domainSelect.options[1] ? domainSelect.options[1].value : "");
    }
    spfProposals.replaceChildren();
    spfSummary.textContent = "";
    spfActions.hidden = true;
    spfDomain.focus();
  }
});
document.getElementById("spf-close-btn").addEventListener("click", () => { spfImport.hidden = true; });

document.getElementById("spf-lookup-btn").addEventListener("click", lookupSpf);
spfDomain.addEventListener("keydown", (e) => { if (e.key === "Enter") lookupSpf(); });

async function lookupSpf() {
  spfSummary.textContent = "Looking up...";
  spfProposals.replaceChildren();
  spfActions.hidden = true;
  try {
    const data = await api("/api/known-senders/from-spf", { method: "POST", body: JSON.stringify({ domain: spfDomain.value, refresh: true }) });
    if (!data.found) {
      spfSummary.textContent = `${data.domain} publishes no SPF record.`;
      return;
    }
    const bits = [`${data.domain}: ${data.record}`, `${data.lookups} of 10 DNS lookups`];
    if (data.tooManyLookups) bits.push("too many lookups - receivers treat this record as broken");
    for (const e of data.errors || []) bits.push(e);
    spfSummary.textContent = bits.join(" | ");

    if (!data.proposals.length) {
      spfProposals.textContent = "The record authorises no networks.";
      return;
    }
    const list = document.createElement("div");
    list.className = "spf-list";
    for (const p of data.proposals) {
      const row = document.createElement("label");
      row.className = "spf-row";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = !p.exists;
      cb.disabled = p.exists;
      cb.dataset.pattern = p.pattern;
      cb.dataset.label = p.label;
      const code = document.createElement("span");
      code.className = "mono";
      code.textContent = p.pattern;
      const via = document.createElement("span");
      via.className = "muted";
      via.textContent = p.exists ? " already known" : ` ${p.label}`;
      row.append(cb, " ", code, via);
      list.appendChild(row);
    }
    spfProposals.replaceChildren(list);
    spfActions.hidden = false;
  } catch (error) {
    spfSummary.textContent = error.message;
  }
}

document.getElementById("spf-add-btn").addEventListener("click", async () => {
  const chosen = [...spfProposals.querySelectorAll("input[type=checkbox]:checked:not(:disabled)")]
    .map((cb) => ({ pattern: cb.dataset.pattern, kind: "ours", label: cb.dataset.label, source: "spf" }));
  if (!chosen.length) {
    setStatus("Tick at least one network first.", true);
    return;
  }
  try {
    const data = await api("/api/known-senders", { method: "POST", body: JSON.stringify({ senders: chosen }) });
    setStatus(`Added ${data.added.length} network${data.added.length === 1 ? "" : "s"} from SPF${data.skipped.length ? `, ${data.skipped.length} skipped` : ""}.`, data.skipped.length > 0);
    spfImport.hidden = true;
    await loadKnownSenders();
    await Promise.all([loadSummary(), loadIps()]);
  } catch (error) {
    setStatus(error.message, true);
  }
});

// --- Exchange Online search helpers ----------------------------------------

const TRACE_LIMIT_DAYS = 10;
const HISTORICAL_LIMIT_DAYS = 90;

function isoUtc(seconds) {
  return new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function psQuote(text) {
  return `"${String(text).replace(/[`"$]/g, "`$&")}"`;
}

function exoSnippet(title, note, code) {
  const item = document.createElement("div");
  item.className = "exo-item";

  const head = document.createElement("div");
  head.className = "exo-item-head";
  const h = document.createElement("strong");
  h.textContent = title;
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "secondary small";
  copy.textContent = "Copy";
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(code);
      copy.textContent = "Copied";
      setTimeout(() => { copy.textContent = "Copy"; }, 1500);
    } catch {
      copy.textContent = "Select and copy";
    }
  });
  head.append(h, copy);
  item.appendChild(head);

  if (note) {
    const p = document.createElement("p");
    p.className = "exo-note";
    p.textContent = note;
    item.appendChild(p);
  }

  const pre = document.createElement("pre");
  pre.className = "exo-code mono";
  pre.textContent = code;
  item.appendChild(pre);
  return item;
}

/**
 * Ready-to-paste Exchange Online queries for the emails behind a report window
 * or a source IP. Message trace results carry FromIP, so an IP filter is exact.
 */
function exoSearchBlock({ begin, end, domain, ip, headerFroms = [] }) {
  const wrap = document.createElement("div");
  wrap.className = "exo";

  const start = isoUtc(begin);
  const stop = isoUtc(end + 1);
  const ageDays = (Date.now() / 1000 - begin) / DAY;
  const domains = domain ? [domain] : headerFroms.filter(Boolean);
  const senderFilter = domains.length === 1
    ? `$_.SenderAddress -like ${psQuote(`*@${domains[0]}`)}`
    : `(${domains.map((d) => `$_.SenderAddress -like ${psQuote(`*@${d}`)}`).join(" -or ")})`;
  const ipFilter = ip ? ` -and $_.FromIP -eq ${psQuote(ip)}` : "";

  const title = document.createElement("h4");
  title.textContent = "Find these emails in Exchange Online";
  wrap.appendChild(title);

  const intro = document.createElement("p");
  intro.className = "exo-note";
  intro.textContent = `Window ${start} to ${stop} (UTC), which is ${formatTimestamp(begin)} to ${formatTimestamp(end + 1)} in your local time. ` +
    "A message trace only sees mail that passed through your tenant: outbound mail your Microsoft 365 sent, or inbound mail your tenant received. " +
    "Mail sent from elsewhere straight to another provider never touched Exchange Online and will not appear.";
  wrap.appendChild(intro);

  const traceNote = ageDays > TRACE_LIMIT_DAYS
    ? `This window is ${Math.floor(ageDays)} days old. Get-MessageTrace only reaches back ${TRACE_LIMIT_DAYS} days, so use the historical search below.`
    : `Message trace covers the last ${TRACE_LIMIT_DAYS} days. FromIP is the sending server, so the IP filter is exact.`;
  wrap.appendChild(exoSnippet("Message trace (PowerShell)", traceNote,
    `Connect-ExchangeOnline\n` +
    `Get-MessageTrace -StartDate ${psQuote(start)} -EndDate ${psQuote(stop)} -PageSize 5000 |\n` +
    `  Where-Object { ${senderFilter}${ipFilter} } |\n` +
    `  Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, FromIP, ToIP, MessageId`));

  const histNote = ageDays > HISTORICAL_LIMIT_DAYS
    ? `This window is older than ${HISTORICAL_LIMIT_DAYS} days, which is as far back as a historical search goes; only an audit log or journal will have it now.`
    : "Runs in the background and emails a CSV. In the CSV, sender_address and original_client_ip are the columns to filter on.";
  const reportTitle = `DMARC ${domains[0] || "report"} ${start.slice(0, 10)}${ip ? ` from ${ip}` : ""}`;
  wrap.appendChild(exoSnippet("Historical search (up to 90 days)", histNote,
    `Start-HistoricalSearch -ReportTitle ${psQuote(reportTitle)} -ReportType MessageTrace \`\n` +
    `  -StartDate ${psQuote(start)} -EndDate ${psQuote(stop)} -NotifyAddress ${psQuote(`you@${domains[0] || "example.com"}`)}\n` +
    `# Later: Get-HistoricalSearch | Sort-Object SubmitDate -Descending | Select-Object -First 1 | Select-Object ReportTitle, Status, FileUrl`));

  const dayStart = start.slice(0, 10);
  const dayEnd = isoUtc(Math.max(begin, end - 1)).slice(0, 10);
  const kqlFrom = domains.length ? ` AND (${domains.map((d) => `from:${d}`).join(" OR ")})` : "";
  wrap.appendChild(exoSnippet("Content search (Purview, KQL)",
    "For mail still sitting in your mailboxes, for example spoofs your own tenant received. Dates are whole days; Purview has no sender-IP field.",
    `sent>=${dayStart} AND sent<=${dayEnd}${kqlFrom}`));

  const portal = document.createElement("p");
  portal.className = "exo-note";
  const link = document.createElement("a");
  link.href = "https://admin.exchange.microsoft.com/#/messagetrace";
  link.target = "_blank";
  link.rel = "noopener";
  link.textContent = "Open message trace in the Exchange admin center";
  portal.append(link, document.createTextNode(` and use a custom range of ${formatTimestamp(begin)} to ${formatTimestamp(end + 1)} (the portal works in your local time).`));
  wrap.appendChild(portal);

  return wrap;
}

// --- reporters -------------------------------------------------------------

async function loadReporters() {
  const data = await api(`/api/reporters${filterQuery()}`);
  const rows = data.reporters || [];
  reportersCount.textContent = `${rows.length} reporter${rows.length === 1 ? "" : "s"}`;
  reportersResults.replaceChildren(buildTable(
    ["Reporter", "Contact", { label: "Reports", className: "num" }, { label: "Messages", className: "num" }, { label: "Failed", className: "num" }, { label: "Fail %", className: "num" }, "First report", "Latest report"],
    rows.map((r) => ({
      data: r,
      cells: [
        textCell(r.orgName),
        textCell(r.orgEmail || "", "mono muted"),
        textCell(formatNumber(r.reports), "num"),
        textCell(formatNumber(r.messages), "num"),
        textCell(formatNumber(r.failed), r.failed ? "num is-fail" : "num"),
        textCell(formatPct(r.failPct), "num"),
        textCell(formatUtcDate(r.firstSeen), "nowrap"),
        textCell(formatUtcDate(Math.max(r.firstSeen, r.lastSeen - 1)), "nowrap")
      ]
    })),
    { emptyText: "No reports in this period." }
  ));

  // Keep the Reports panel's reporter dropdown in step with who actually reported.
  const current = reporterFilter.value;
  reporterFilter.replaceChildren();
  const all = document.createElement("option");
  all.value = "";
  all.textContent = "All";
  reporterFilter.appendChild(all);
  for (const r of rows) {
    const opt = document.createElement("option");
    opt.value = r.orgName;
    opt.textContent = r.orgName;
    reporterFilter.appendChild(opt);
  }
  reporterFilter.value = current;
  if (reporterFilter.value !== current) reporterFilter.value = "";
}

// --- reports ---------------------------------------------------------------

async function loadReports() {
  const data = await api(`/api/reports${filterQuery({ org: reporterFilter.value, page: reportsPage, pageSize: reportsPageSize })}`);
  const rows = data.rows || [];
  reportsCount.textContent = `${formatNumber(data.total)} report${data.total === 1 ? "" : "s"}`;
  const pages = Math.max(1, Math.ceil(data.total / data.pageSize));
  reportsPageLabel.textContent = `Page ${data.page} of ${pages}`;
  reportsPrev.disabled = data.page <= 1;
  reportsNext.disabled = data.page >= pages;

  reportsResults.replaceChildren(buildTable(
    ["Window", "Reporter", "Domain", "Policy", { label: "Messages", className: "num" }, { label: "Failed", className: "num" }, "Received", ...(mailboxNames.size > 1 ? ["Mailbox"] : []), "Report ID"],
    rows.map((r) => ({
      data: r,
      cells: [
        textCell(formatWindow(r.rangeBegin, r.rangeEnd), "nowrap"),
        textCell(r.orgName, "nowrap"),
        textCell(r.domain, "mono"),
        textCell(`p=${r.p || "?"}${r.pct !== null && r.pct !== 100 ? ` pct=${r.pct}` : ""}`, "mono muted"),
        textCell(formatNumber(r.messages), "num"),
        textCell(formatNumber(r.failed), r.failed ? "num is-fail" : "num"),
        textCell(r.receivedAt ? formatTimestamp(r.receivedAt) : formatTimestamp(r.ingestedAt), "nowrap"),
        ...(mailboxNames.size > 1 ? [textCell(mailboxName(r.mailboxId), "nowrap")] : []),
        textCell(r.reportId, "mono muted trunc")
      ]
    })),
    { emptyText: "No reports in this period.", onRowClick: (r) => openReportDetail(r.id) }
  ));
}

reportsPrev.addEventListener("click", () => { reportsPage = Math.max(1, reportsPage - 1); loadReports(); });
reportsNext.addEventListener("click", () => { reportsPage += 1; loadReports(); });

async function openReportDetail(id) {
  try {
    const r = await api(`/api/reports/${encodeURIComponent(id)}`);
    reportDetailTitle.textContent = `${r.orgName} - ${formatWindow(r.rangeBegin, r.rangeEnd)} - ${r.domain}`;
    reportDetailXml.href = `/api/reports/${encodeURIComponent(id)}/xml`;
    reportDetailSummary.replaceChildren(
      kv("Report ID", r.reportId),
      kv("Window (UTC)", `${formatUtcDateTime(r.rangeBegin)} to ${formatUtcDateTime(r.rangeEnd)}`),
      kv("Published policy", `p=${r.p || "?"} sp=${r.sp || "?"} pct=${r.pct ?? "?"} adkim=${r.adkim || "?"} aspf=${r.aspf || "?"}`),
      kv("Messages", `${formatNumber(r.messages)} (${formatNumber(r.failed)} failed)`),
      kv("Contact", r.orgEmail || "-"),
      kv("Email received", r.receivedAt ? formatTimestamp(r.receivedAt) : "-"),
      kv("Subject", r.subject || "-"),
      kv("Attachment", r.attachmentName || "-")
    );
    reportDetailExo.replaceChildren(exoSearchBlock({ begin: r.rangeBegin, end: r.rangeEnd, domain: r.domain }));
    reportDetailBody.replaceChildren(buildTable(
      ["Window", "Reporter", "Source IP", { label: "Count", className: "num" }, "Result", "SPF / DKIM", "Header From", "Envelope From", "Auth results", "Reasons"],
      recordRows(r.records || [], { showIp: true }),
      { expand: (rec) => exoSearchBlock({ begin: rec.rangeBegin, end: rec.rangeEnd, ip: rec.sourceIp, domain: rec.domain, headerFroms: [rec.headerFrom] }) }
    ));
    reportDetail.hidden = false;
    reportDetail.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (error) {
    setStatus(error.message, true);
  }
}

document.getElementById("report-detail-close").addEventListener("click", () => { reportDetail.hidden = true; });

// --- sync ------------------------------------------------------------------

function describeRun(run) {
  if (!run) return "never";
  const when = formatTimestamp(run.finished_at || run.started_at);
  if (!run.finished_at) return `running since ${when}`;
  if (run.error_text && !run.reports_added && !run.messages_seen) return `${when} failed: ${run.error_text}`;
  const parts = [`${run.reports_added} added`];
  if (run.duplicates) parts.push(`${run.duplicates} duplicate${run.duplicates === 1 ? "" : "s"}`);
  if (run.errors) parts.push(`${run.errors} error${run.errors === 1 ? "" : "s"}`);
  return `${when} (${parts.join(", ")})`;
}

let mailboxList = [];
const mailboxNames = new Map();

function mailboxName(id) {
  return mailboxNames.get(id) || id || "";
}

function isAdmin() {
  return Boolean(currentUser) && currentUser.role === "admin";
}

/** Keeps the filter-bar dropdown in step with the configured mailboxes; hidden when there is only one. */
function populateMailboxSelect(list, counts) {
  mailboxNames.clear();
  for (const m of list) mailboxNames.set(m.id, m.name);
  const known = new Map(list.map((m) => [m.id, m]));
  // Reports may belong to a mailbox that was deleted since; keep it selectable.
  for (const c of counts || []) {
    if (!known.has(c.id)) mailboxNames.set(c.id, `${c.id} (removed)`);
  }
  const current = mailboxSelect.value;
  mailboxSelect.replaceChildren();
  const all = document.createElement("option");
  all.value = "";
  all.textContent = "All mailboxes";
  mailboxSelect.appendChild(all);
  for (const [id, name] of mailboxNames) {
    const opt = document.createElement("option");
    opt.value = id;
    opt.textContent = name;
    mailboxSelect.appendChild(opt);
  }
  mailboxSelect.value = current;
  if (mailboxSelect.value !== current) mailboxSelect.value = "";
  mailboxLabel.hidden = mailboxNames.size < 2;
}

function renderMailboxes(list) {
  mailboxList = list;
  const admin = isAdmin();
  mailboxesResults.replaceChildren(buildTable(
    ["Name", "Mailbox", "Folder", "Tenant", "Last sync", { label: "Reports", className: "num" }, "State", ""],
    list.map((m) => {
      const actions = document.createElement("td");
      const wrap = document.createElement("div");
      wrap.className = "row-actions";
      if (canWrite() && m.enabled) {
        const syncBtn = document.createElement("button");
        syncBtn.className = "secondary small";
        syncBtn.textContent = "Sync";
        syncBtn.addEventListener("click", () => startSync({ mailboxId: m.id }));
        wrap.appendChild(syncBtn);
      }
      if (admin) {
        const testBtn = document.createElement("button");
        testBtn.className = "secondary small";
        testBtn.textContent = "Test";
        testBtn.addEventListener("click", async () => {
          testBtn.disabled = true;
          showSyncMessage(`Testing ${m.name}...`);
          try {
            const result = await api(`/api/mailboxes/${encodeURIComponent(m.id)}/test`, { method: "POST", body: "{}" });
            showSyncMessage(result.ok ? `${m.name}: ${result.detail}` : `${m.name}: connection test failed (${result.stage}): ${result.detail}`, !result.ok);
          } catch (error) {
            showSyncMessage(error.message, true);
          } finally {
            testBtn.disabled = false;
          }
        });
        wrap.appendChild(testBtn);
        if (!m.readOnly) {
          const editBtn = document.createElement("button");
          editBtn.className = "secondary small";
          editBtn.textContent = "Edit";
          editBtn.addEventListener("click", () => openMailboxForm(m));
          wrap.appendChild(editBtn);
          const delBtn = document.createElement("button");
          delBtn.className = "ghost-danger small";
          delBtn.textContent = "Delete";
          delBtn.addEventListener("click", async () => {
            if (!confirm(`Remove the mailbox "${m.name}"?\n\nReports already ingested from it stay in the database.`)) return;
            try {
              await api(`/api/mailboxes/${encodeURIComponent(m.id)}`, { method: "DELETE" });
              showSyncMessage(`Removed ${m.name}.`);
              await loadSyncStatus();
            } catch (error) {
              showSyncMessage(error.message, true);
            }
          });
          wrap.appendChild(delBtn);
        }
      }
      actions.appendChild(wrap);
      return {
        data: m,
        cells: [
          textCell(m.name + (m.readOnly ? " (env)" : ""), "nowrap"),
          textCell(m.mailbox, "mono"),
          textCell(m.folder || "Inbox"),
          textCell(m.tenantId, "mono muted trunc"),
          textCell(describeRun(m.lastRun), m.lastRun?.error_text ? "muted trunc-wide is-fail" : "muted trunc-wide"),
          textCell(m.counts ? formatNumber(m.counts.reports) : "0", "num"),
          textCell(m.enabled ? "enabled" : "disabled", m.enabled ? "" : "muted"),
          actions
        ]
      };
    }),
    { emptyText: isAdmin() ? "No mailboxes yet. Add one below, or set the GRAPH_* and DMARC_MAILBOX environment variables." : "No mailboxes configured. An administrator can add one here." }
  ));
}

function renderSyncStatus(st) {
  const list = st.mailboxes || [];
  populateMailboxSelect(list, st.mailboxCounts || []);
  renderMailboxes(list);

  graphConfig.replaceChildren(
    kvRow("Scheduled sync", st.scheduler?.enabled ? `every ${st.scheduler.intervalMinutes} min` : "off"),
    kvRow("Backfill window", `${st.backfillDays} days on a mailbox's first sync`),
    kvRow("Last run", describeRun(st.lastRun)),
    kvRow("Stored", `${formatNumber(st.stats?.reports?.reports)} reports from ${formatNumber(st.stats?.messages?.ingested)} emails`)
  );

  const usable = st.configured && canWrite();
  syncNowBtn.disabled = !usable;
  backfillBtn.disabled = !usable;
  if (!st.configured && !list.length) {
    showSyncMessage(isAdmin()
      ? "No mailbox is configured yet. Add one with the button below (you need the tenant ID, client ID, client secret and mailbox address from the Entra app registration; see the README)."
      : "No mailbox is configured yet. Ask an administrator to add one.", true);
  }

  const runs = st.runs || [];
  runsResults.replaceChildren(buildTable(
    ["Started", "Mailbox", "Trigger", { label: "Seen", className: "num" }, { label: "Added", className: "num" }, { label: "Duplicates", className: "num" }, { label: "Errors", className: "num" }, "Outcome"],
    runs.map((r) => ({
      data: r,
      cells: [
        textCell(formatTimestamp(r.started_at), "nowrap"),
        textCell(mailboxName(r.mailbox_id), "nowrap"),
        textCell(r.trigger),
        textCell(formatNumber(r.messages_seen), "num"),
        textCell(formatNumber(r.reports_added), "num"),
        textCell(formatNumber(r.duplicates), "num"),
        textCell(formatNumber(r.errors), r.errors ? "num is-fail" : "num"),
        textCell(!r.finished_at ? "running" : r.error_text ? r.error_text : "ok", r.error_text ? "muted trunc-wide" : "muted")
      ]
    })),
    { emptyText: "No sync has run yet." }
  ));

  const errors = st.errors || [];
  errorsResults.replaceChildren(buildTable(
    ["Received", "From", "Subject", "Problem"],
    errors.map((m) => ({
      data: m,
      cells: [textCell(formatTimestamp(m.received_at), "nowrap"), textCell(m.from_addr || "", "mono"), textCell(m.subject || "", "trunc"), textCell(m.error || "", "muted trunc-wide")]
    })),
    { emptyText: "None." }
  ));

  if (st.currentJob && st.currentJob.status === "running") {
    trackJob(st.currentJob.id);
  }
}

// --- mailbox add / edit form -------------------------------------------------

let editingMailboxId = null;

function openMailboxForm(m) {
  editingMailboxId = m ? m.id : null;
  mailboxFormTitle.textContent = m ? `Edit ${m.name}` : "Add a mailbox";
  document.getElementById("mb-name").value = m ? m.name : "";
  document.getElementById("mb-tenant").value = m ? m.tenantId : "";
  document.getElementById("mb-client").value = m ? m.clientId : "";
  document.getElementById("mb-secret").value = "";
  document.getElementById("mb-secret").placeholder = m ? "leave blank to keep the current secret" : "";
  document.getElementById("mb-mailbox").value = m ? m.mailbox : "";
  document.getElementById("mb-folder").value = m ? m.folder || "Inbox" : "Inbox";
  document.getElementById("mb-enabled").checked = m ? Boolean(m.enabled) : true;
  mailboxForm.hidden = false;
  mailboxForm.scrollIntoView({ behavior: "smooth", block: "nearest" });
  document.getElementById("mb-name").focus();
}

function closeMailboxForm() {
  mailboxForm.hidden = true;
  editingMailboxId = null;
}

addMailboxBtn.addEventListener("click", () => openMailboxForm(null));
document.getElementById("mb-cancel").addEventListener("click", closeMailboxForm);

document.getElementById("mb-save").addEventListener("click", async () => {
  const body = {
    name: document.getElementById("mb-name").value,
    tenantId: document.getElementById("mb-tenant").value,
    clientId: document.getElementById("mb-client").value,
    clientSecret: document.getElementById("mb-secret").value,
    mailbox: document.getElementById("mb-mailbox").value,
    folder: document.getElementById("mb-folder").value,
    enabled: document.getElementById("mb-enabled").checked
  };
  try {
    const data = editingMailboxId
      ? await api(`/api/mailboxes/${encodeURIComponent(editingMailboxId)}`, { method: "PUT", body: JSON.stringify(body) })
      : await api("/api/mailboxes", { method: "POST", body: JSON.stringify(body) });
    closeMailboxForm();
    showSyncMessage(`${editingMailboxId ? "Saved" : "Added"} ${data.mailbox.name}. Use Test to check the connection, then Sync.`);
    await loadSyncStatus();
  } catch (error) {
    showSyncMessage(error.message, true);
  }
});

function kvRow(label, value) {
  const wrap = document.createDocumentFragment();
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = value;
  wrap.append(dt, dd);
  return wrap;
}

function showSyncMessage(text, isError = false) {
  syncMessage.textContent = text || "";
  syncMessage.hidden = !text;
  syncMessage.classList.toggle("is-error", isError);
}

function setSyncBusy(busy) {
  syncNowBtn.disabled = busy || !canWrite();
  backfillBtn.disabled = busy || !canWrite();
  syncProgress.hidden = !busy;
  syncState.textContent = busy ? "Running" : "Idle";
  syncState.classList.toggle("badge-live", busy);
}

function describeJob(job) {
  const bits = [`${job.seen} new message${job.seen === 1 ? "" : "s"} read`, `${job.added} report${job.added === 1 ? "" : "s"} added`];
  if (job.skipped) bits.push(`${job.skipped} already seen`);
  if (job.duplicates) bits.push(`${job.duplicates} duplicate${job.duplicates === 1 ? "" : "s"}`);
  if (job.noReport) bits.push(`${job.noReport} without a report`);
  if (job.errors) bits.push(`${job.errors} error${job.errors === 1 ? "" : "s"}`);
  return bits.join(", ");
}

function renderJobMailboxes(job) {
  syncProgressList.replaceChildren();
  for (const b of job.mailboxes || []) {
    const li = document.createElement("li");
    const state = b.status === "failed" ? `failed: ${b.error}` : b.status === "pending" ? "waiting" : b.status === "running" ? "reading..." : "done";
    li.textContent = `${b.name}: ${state}${b.status !== "pending" ? ` (${b.added} added, ${b.seen} read${b.errors ? `, ${b.errors} errors` : ""})` : ""}`;
    if (b.status === "failed") li.className = "is-error";
    syncProgressList.appendChild(li);
  }
}

async function trackJob(jobId) {
  if (syncPollTimer) {
    return;
  }
  setSyncBusy(true);
  showSyncMessage("");
  const poll = async () => {
    try {
      const job = await api(`/api/sync/${encodeURIComponent(jobId)}`);
      syncProgressText.textContent = `${describeJob(job)}${job.current ? ` - reading "${job.current}"` : ""}`;
      renderJobMailboxes(job);
      if (job.status === "running") {
        syncPollTimer = setTimeout(poll, JOB_POLL_MS);
        return;
      }
      syncPollTimer = null;
      setSyncBusy(false);
      if (job.status === "failed") {
        showSyncMessage(`Sync failed: ${job.error}`, true);
      } else {
        showSyncMessage(`Sync finished: ${describeJob(job)}.${job.lastError ? ` Problem: ${job.lastError}` : ""}`, job.errors > 0 || Boolean(job.lastError));
      }
      await loadAll();
    } catch (error) {
      syncPollTimer = null;
      setSyncBusy(false);
      showSyncMessage(error.message, true);
    }
  };
  syncPollTimer = setTimeout(poll, 300);
}

async function startSync(body) {
  try {
    const data = await api("/api/sync", { method: "POST", body: JSON.stringify(body || {}) });
    if (data.alreadyRunning) {
      showSyncMessage("A sync is already running.");
    }
    trackJob(data.jobId);
  } catch (error) {
    showSyncMessage(error.message, true);
  }
}

syncNowBtn.addEventListener("click", () => startSync({}));
backfillBtn.addEventListener("click", () => {
  if (!backfillDate.value) {
    showSyncMessage("Pick the date to re-scan from first.", true);
    return;
  }
  startSync({ since: backfillDate.value });
});

async function loadSyncStatus() {
  const [st, runs] = await Promise.all([api("/api/status"), api("/api/sync/runs?limit=15")]);
  renderSyncStatus({ ...st, runs: runs.runs });
}

// --- load everything -------------------------------------------------------

async function loadAll() {
  const range = currentRange();
  rangeLabel.textContent = range.label + (domainSelect.value ? ` - ${domainSelect.value}` : "");
  setStatus("Loading...");
  const tasks = [
    ["summary", loadSummary],
    ["sources", loadIps],
    ["reporters", loadReporters],
    ["known senders", loadKnownSenders],
    ["alerts", loadAlerts],
    ["reports", loadReports],
    ["sync status", loadSyncStatus]
  ];
  const problems = [];
  await Promise.all(tasks.map(async ([name, fn]) => {
    try {
      await fn();
    } catch (error) {
      problems.push(`${name}: ${error.message}`);
    }
  }));
  if (problems.length) {
    setStatus(problems.join(" | "), true);
  } else {
    setStatus(`Updated ${formatTimestamp(Math.floor(Date.now() / 1000))}`);
  }
}

// --- authentication --------------------------------------------------------

const authOverlay = document.getElementById("auth-overlay");
const authTitle = document.getElementById("auth-title");
const authMessage = document.getElementById("auth-message");
const authLoginForm = document.getElementById("auth-login-form");
const authMfaForm = document.getElementById("auth-mfa-form");
const authRecoveryForm = document.getElementById("auth-recovery-form");
const authSetupForm = document.getElementById("auth-setup-form");
const authEnrol = document.getElementById("auth-enrol");
const authRecoveryCodes = document.getElementById("auth-recovery-codes");

const currentUserEl = document.getElementById("current-user");
const accountBtn = document.getElementById("account-btn");
const usersBtn = document.getElementById("users-btn");
const logoutBtn = document.getElementById("logout-btn");
const usersPanel = document.getElementById("users-panel");
const accountPanel = document.getElementById("account-panel");
const usersResultsEl = document.getElementById("users-results");
const usersCountEl = document.getElementById("users-count");

let pendingLoginToken = null;
let issuedRecoveryCodes = [];

const AUTH_STEPS = {
  login: authLoginForm,
  mfa: authMfaForm,
  recovery: authRecoveryForm,
  setup: authSetupForm,
  enrol: authEnrol,
  codes: authRecoveryCodes
};

const AUTH_TITLES = {
  login: "Sign in",
  mfa: "Two-factor authentication",
  recovery: "Use a recovery code",
  setup: "Welcome - create your administrator",
  enrol: "Set up two-factor authentication",
  codes: "Save your recovery codes"
};

function showAuthOverlay(step) {
  authOverlay.hidden = false;
  document.body.classList.add("auth-locked");
  setAuthStep(step);
}

function hideAuthOverlay() {
  authOverlay.hidden = true;
  document.body.classList.remove("auth-locked");
  setAuthMessage("");
}

function setAuthStep(step) {
  for (const [name, el] of Object.entries(AUTH_STEPS)) {
    el.hidden = name !== step;
  }
  authTitle.textContent = AUTH_TITLES[step] || "Sign in";
  setAuthMessage("");

  const focus = {
    login: "auth-username", mfa: "auth-mfa-code", recovery: "auth-recovery-code",
    setup: "setup-username", enrol: "enrol-code"
  }[step];
  if (focus) {
    setTimeout(() => document.getElementById(focus)?.focus(), 30);
  }
}

function setAuthMessage(text, isError = true) {
  authMessage.textContent = text || "";
  authMessage.hidden = !text;
  authMessage.classList.toggle("is-error", isError);
}

const ROLE_LABEL = { admin: "Administrator", user: "User", viewer: "Viewer (read-only)" };

function canWrite() {
  return Boolean(currentUser) && currentUser.role !== "viewer";
}

/** Applies the signed-in identity to the chrome and reveals role-gated controls. */
function applyIdentity(user, token) {
  currentUser = user;
  csrfToken = token;
  document.body.classList.toggle("role-viewer", Boolean(user) && user.role === "viewer");

  const signedIn = Boolean(user);
  currentUserEl.hidden = !signedIn;
  accountBtn.hidden = !signedIn;
  logoutBtn.hidden = !signedIn;
  usersBtn.hidden = !signedIn || user.role !== "admin";
  addMailboxBtn.hidden = !signedIn || user.role !== "admin";
  if (!signedIn) mailboxForm.hidden = true;

  if (signedIn) {
    currentUserEl.textContent = user.role === "user" ? user.username : `${user.username} (${user.role})`;
  }

  if (!signedIn) {
    usersPanel.hidden = true;
    accountPanel.hidden = true;
  }
}

async function refreshIdentity() {
  const me = await (await fetch("/api/auth/me")).json();

  if (me.setupRequired) {
    applyIdentity(null, null);
    showAuthOverlay("setup");
    return false;
  }

  if (!me.authenticated) {
    applyIdentity(null, null);
    showAuthOverlay("login");
    return false;
  }

  applyIdentity(me.user, me.csrfToken);
  hideAuthOverlay();
  return true;
}

authSetupForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("setup-username").value.trim();
  const password = document.getElementById("setup-password").value;
  const confirm2 = document.getElementById("setup-password2").value;

  if (password !== confirm2) {
    setAuthMessage("Passwords do not match.");
    return;
  }

  try {
    const data = await api("/api/auth/setup", { method: "POST", body: JSON.stringify({ username, password }) });
    applyIdentity(data.user, data.csrfToken);
    await beginEnrolment();
  } catch (error) {
    setAuthMessage(error.message);
  }
});

authLoginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("auth-username").value.trim();
  const password = document.getElementById("auth-password").value;

  try {
    const data = await api("/api/auth/login", { method: "POST", body: JSON.stringify({ username, password }) });
    document.getElementById("auth-password").value = "";

    if (data.mfaRequired) {
      pendingLoginToken = data.pendingToken;
      setAuthStep("mfa");
      return;
    }

    applyIdentity(data.user, data.csrfToken);
    if (data.mfaSetupRequired) {
      await beginEnrolment();
      return;
    }
    await onSignedIn();
  } catch (error) {
    setAuthMessage(error.message);
  }
});

authMfaForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const data = await api("/api/auth/login/mfa", {
      method: "POST",
      body: JSON.stringify({ pendingToken: pendingLoginToken, code: document.getElementById("auth-mfa-code").value })
    });
    document.getElementById("auth-mfa-code").value = "";
    applyIdentity(data.user, data.csrfToken);
    await onSignedIn();
  } catch (error) {
    setAuthMessage(error.message);
  }
});

authRecoveryForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const data = await api("/api/auth/login/recovery", {
      method: "POST",
      body: JSON.stringify({ pendingToken: pendingLoginToken, code: document.getElementById("auth-recovery-code").value })
    });
    document.getElementById("auth-recovery-code").value = "";
    applyIdentity(data.user, data.csrfToken);
    await onSignedIn();
    setStatus(`Signed in with a recovery code. ${data.recoveryCodesRemaining} remaining.`, data.recoveryCodesRemaining === 0);
  } catch (error) {
    setAuthMessage(error.message);
  }
});

document.getElementById("auth-use-recovery").addEventListener("click", () => setAuthStep("recovery"));
document.getElementById("auth-use-totp").addEventListener("click", () => setAuthStep("mfa"));

async function beginEnrolment() {
  try {
    const data = await api("/api/auth/mfa/setup", { method: "POST", body: "{}" });
    document.getElementById("enrol-qr").src = data.qrDataUrl;
    document.getElementById("enrol-secret").value = data.secret;
    showAuthOverlay("enrol");
  } catch (error) {
    setAuthMessage(error.message);
  }
}

document.getElementById("enrol-confirm").addEventListener("click", async () => {
  try {
    const data = await api("/api/auth/mfa/confirm", {
      method: "POST",
      body: JSON.stringify({ code: document.getElementById("enrol-code").value })
    });
    issuedRecoveryCodes = data.recoveryCodes || [];
    document.getElementById("recovery-code-list").textContent = issuedRecoveryCodes.join("\n");
    setAuthStep("codes");
  } catch (error) {
    setAuthMessage(error.message);
  }
});

document.getElementById("enrol-skip").addEventListener("click", async () => {
  await onSignedIn();
});

document.getElementById("recovery-copy").addEventListener("click", () => {
  navigator.clipboard?.writeText(issuedRecoveryCodes.join("\n"));
  setAuthMessage("Copied to clipboard.", false);
});

document.getElementById("recovery-download").addEventListener("click", () => {
  const blob = new Blob([issuedRecoveryCodes.join("\r\n")], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "dmarc-analyzer-recovery-codes.txt";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

document.getElementById("recovery-done").addEventListener("click", async () => {
  issuedRecoveryCodes = [];
  await onSignedIn();
});

logoutBtn.addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST", body: "{}" });
  } catch {
    // Signing out locally is what matters even if the call failed.
  }
  applyIdentity(null, null);
  clearTimeout(syncPollTimer);
  syncPollTimer = null;
  for (const el of [statGrid, ipsResults, reportersResults, reportsResults, runsResults, errorsResults, graphConfig]) {
    el.replaceChildren();
  }
  chartSvg.replaceChildren();
  ipDetail.hidden = true;
  reportDetail.hidden = true;
  alertsBanner.hidden = true;
  document.title = BASE_TITLE;
  showAuthOverlay("login");
});

accountBtn.addEventListener("click", () => {
  accountPanel.hidden = !accountPanel.hidden;
  usersPanel.hidden = true;
  if (!accountPanel.hidden) {
    renderAccountPanel();
    accountPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  }
});

usersBtn.addEventListener("click", async () => {
  usersPanel.hidden = !usersPanel.hidden;
  accountPanel.hidden = true;
  if (!usersPanel.hidden) {
    await refreshUsers();
    usersPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  }
});

function renderAccountPanel() {
  const enrolled = Boolean(currentUser?.mfaEnrolled);
  document.getElementById("account-mfa-state").textContent = `Two-factor: ${enrolled ? "on" : "off"}`;
  document.getElementById("acct-enable-mfa").hidden = enrolled;
  document.getElementById("acct-disable-mfa").hidden = !enrolled;
}

document.getElementById("acct-enable-mfa").addEventListener("click", beginEnrolment);

document.getElementById("acct-disable-mfa").addEventListener("click", async () => {
  const password = prompt("Confirm your password to turn off two-factor authentication:");
  if (!password) {
    return;
  }
  try {
    await api("/api/auth/mfa/disable", { method: "POST", body: JSON.stringify({ password }) });
    await refreshIdentity();
    renderAccountPanel();
    setStatus("Two-factor authentication turned off.", true);
  } catch (error) {
    setStatus(error.message, true);
  }
});

document.getElementById("acct-change-password").addEventListener("click", async () => {
  const currentPassword = document.getElementById("acct-current").value;
  const newPassword = document.getElementById("acct-new").value;
  try {
    await api("/api/auth/password", { method: "POST", body: JSON.stringify({ currentPassword, newPassword }) });
    document.getElementById("acct-current").value = "";
    document.getElementById("acct-new").value = "";
    setStatus("Password changed.");
  } catch (error) {
    setStatus(error.message, true);
  }
});

async function refreshUsers() {
  const data = await api("/api/users");
  const users = data.users || [];
  usersCountEl.textContent = `${users.length} user${users.length === 1 ? "" : "s"}`;
  usersResultsEl.replaceChildren();

  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  for (const label of ["Username", "Role", "Two-factor", "Last sign-in", ""]) {
    const th = document.createElement("th");
    th.textContent = label;
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  for (const user of users) {
    const tr = document.createElement("tr");
    for (const text of [
      user.username,
      ROLE_LABEL[user.role] || user.role,
      user.mfaEnrolled ? "Enabled" : "Not set up",
      user.lastLoginAt ? formatTimestamp(user.lastLoginAt) : "Never"
    ]) {
      tr.appendChild(textCell(text));
    }

    const actions = document.createElement("td");
    const wrap = document.createElement("div");
    wrap.className = "row-actions";

    const resetBtn2 = document.createElement("button");
    resetBtn2.className = "secondary small";
    resetBtn2.textContent = "Reset MFA";
    resetBtn2.addEventListener("click", async () => {
      if (!confirm(`Reset two-factor for "${user.username}"?\n\nThey will sign in with their password alone until they enrol again.`)) {
        return;
      }
      try {
        await api(`/api/users/${encodeURIComponent(user.id)}/reset-mfa`, { method: "POST", body: "{}" });
        await refreshUsers();
        setStatus(`Two-factor reset for ${user.username}.`);
      } catch (error) {
        setStatus(error.message, true);
      }
    });
    wrap.appendChild(resetBtn2);

    if (user.id !== currentUser?.id) {
      const roleSelect = document.createElement("select");
      roleSelect.className = "small";
      roleSelect.title = "Change role";
      for (const [value, label] of Object.entries(ROLE_LABEL)) {
        const opt = document.createElement("option");
        opt.value = value;
        opt.textContent = label;
        opt.selected = value === user.role;
        roleSelect.appendChild(opt);
      }
      roleSelect.addEventListener("change", async () => {
        try {
          await api(`/api/users/${encodeURIComponent(user.id)}/role`, { method: "POST", body: JSON.stringify({ role: roleSelect.value }) });
          await refreshUsers();
          setStatus(`${user.username} is now ${ROLE_LABEL[roleSelect.value].toLowerCase()}.`);
        } catch (error) {
          setStatus(error.message, true);
          roleSelect.value = user.role;
        }
      });
      wrap.appendChild(roleSelect);

      const del = document.createElement("button");
      del.className = "ghost-danger small";
      del.textContent = "Delete";
      del.addEventListener("click", async () => {
        if (!confirm(`Delete the account "${user.username}"?\n\nThis cannot be undone.`)) {
          return;
        }
        try {
          await api(`/api/users/${encodeURIComponent(user.id)}`, { method: "DELETE" });
          await refreshUsers();
          setStatus(`Deleted ${user.username}.`);
        } catch (error) {
          setStatus(error.message, true);
        }
      });
      wrap.appendChild(del);
    }

    actions.appendChild(wrap);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  }

  table.appendChild(tbody);
  usersResultsEl.appendChild(table);
}

document.getElementById("add-user-btn").addEventListener("click", async () => {
  const username = document.getElementById("new-username").value.trim();
  const password = document.getElementById("new-password").value;
  const role = document.getElementById("new-role").value;

  try {
    await api("/api/users", { method: "POST", body: JSON.stringify({ username, password, role }) });
    document.getElementById("new-username").value = "";
    document.getElementById("new-password").value = "";
    await refreshUsers();
    setStatus(`Added ${username}. They should enrol two-factor at first sign-in.`);
  } catch (error) {
    setStatus(error.message, true);
  }
});

/** Loads everything the signed-in app needs. */
async function onSignedIn() {
  hideAuthOverlay();
  renderAccountPanel();
  try {
    await loadDomains();
    const st = await api("/api/status");
    populateMailboxSelect(st.mailboxes || [], st.mailboxCounts || []);
  } catch (_) {
    // The dropdowns are a convenience; the rest still loads.
  }
  await loadAll();
}

(async function init() {
  applyTheme(localStorage.getItem("dmarc-theme") || "light");
  hideForwards.checked = localStorage.getItem("dmarc-hide-forwards") === "1";
  const savedRange = localStorage.getItem("dmarc-range");
  if (savedRange && [...rangeSelect.options].some((o) => o.value === savedRange)) {
    rangeSelect.value = savedRange;
  }
  const custom = rangeSelect.value === "custom";
  fromLabel.hidden = !custom;
  toLabel.hidden = !custom;
  if (custom) {
    fromDate.value = formatUtcDate(todayUtcStart() - 30 * DAY);
    toDate.value = formatUtcDate(todayUtcStart());
  }

  // Nothing loads until we know who (if anyone) is signed in.
  const signedIn = await refreshIdentity();
  if (signedIn) {
    await onSignedIn();
  }
})();
