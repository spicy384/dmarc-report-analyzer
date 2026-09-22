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

const statGrid = document.getElementById("stat-grid");
const chartWrap = document.getElementById("chart-wrap");
const chartSvg = document.getElementById("chart");
const chartTip = document.getElementById("chart-tip");
const chartEmpty = document.getElementById("chart-empty");

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

const syncState = document.getElementById("sync-state");
const graphConfig = document.getElementById("graph-config");
const syncNowBtn = document.getElementById("sync-now-btn");
const testGraphBtn = document.getElementById("test-graph-btn");
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

function buildTable(headers, rows, { emptyText = "Nothing to show.", onRowClick } = {}) {
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
    if (onRowClick) {
      tr.className = "clickable";
      tr.tabIndex = 0;
      tr.addEventListener("click", () => onRowClick(row.data));
      tr.addEventListener("keydown", (e) => {
        if (e.key === "Enter") onRowClick(row.data);
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
refreshBtn.addEventListener("click", () => loadAll());
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

function statTile(label, value, { sub = "", tone = "" } = {}) {
  const div = document.createElement("div");
  div.className = `stat${tone ? " stat-" + tone : ""}`;
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

function renderStats(t) {
  statGrid.replaceChildren(
    statTile("Messages", formatNumber(t.messages), { sub: `${formatNumber(t.reports)} reports` }),
    statTile("DMARC pass", formatPct(t.passPct), { sub: `${formatNumber(t.passed)} messages`, tone: "pass" }),
    statTile("DMARC fail", formatPct(t.failPct), { sub: `${formatNumber(t.failed)} messages`, tone: t.failed > 0 ? "fail" : "" }),
    statTile("Quarantined", formatNumber(t.quarantined), { tone: t.quarantined > 0 ? "quarantine" : "" }),
    statTile("Rejected", formatNumber(t.rejected), { tone: t.rejected > 0 ? "reject" : "" }),
    statTile("Failing sources", formatNumber(t.failingIps), { sub: `of ${formatNumber(t.sourceIps)} source IPs` }),
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
    out.push(byDay.get(key) || { day: key, total: 0, pass: 0, failNone: 0, failQuarantine: 0, failReject: 0, fail: 0 });
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
    for (const [key, color] of [["pass", colors.pass], ["failNone", colors.failNone], ["failQuarantine", colors.failQuarantine], ["failReject", colors.failReject]]) {
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
    const failed = (d.failNone || 0) + (d.failQuarantine || 0) + (d.failReject || 0);
    chartTip.innerHTML = "";
    const title = document.createElement("strong");
    title.textContent = d.day;
    chartTip.appendChild(title);
    for (const [label, v] of [["Messages", d.total], ["Pass", d.pass], ["Fail", failed], ["Quarantined", d.failQuarantine], ["Rejected", d.failReject]]) {
      const line = document.createElement("div");
      line.textContent = `${label}: ${formatNumber(v)}`;
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
  renderStats(data.totals);
  renderChart(data.days || []);
  return data;
}

// --- sources ---------------------------------------------------------------

function ipRow(r) {
  const dispositions = [];
  if (r.failNone) dispositions.push(`${formatNumber(r.failNone)} delivered`);
  if (r.quarantined) dispositions.push(`${formatNumber(r.quarantined)} quarantined`);
  if (r.rejected) dispositions.push(`${formatNumber(r.rejected)} rejected`);

  const failCell = textCell(formatNumber(r.failed), r.failed > 0 ? "num is-fail" : "num");
  return {
    data: r,
    cells: [
      textCell(r.ip, "mono"),
      textCell(r.ptr || "", "mono muted"),
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
    ["Source IP", "Reverse DNS", { label: "Messages", className: "num" }, { label: "Failed", className: "num" }, { label: "Fail %", className: "num" },
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
      (() => { const td = document.createElement("td"); td.appendChild(resultBadge(rec.passed, rec.disposition)); return td; })(),
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
      kv("Reported by", d.reporterNames.join(", ")),
      kv("Header From", d.headerFroms.join(", ") || "-"),
      kv("Envelope From", d.envelopeFroms.join(", ") || "-"),
      kv("SPF domains", d.spfDomains.join(", ") || "-"),
      kv("DKIM domains", d.dkimDomains.join(", ") || "-")
    );
    ipDetailBody.replaceChildren(buildTable(
      ["Window", "Reporter", { label: "Count", className: "num" }, "Result", "SPF / DKIM", "Header From", "Envelope From", "Auth results", "Reasons"],
      recordRows(d.records || [])
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
    ["Window", "Reporter", "Domain", "Policy", { label: "Messages", className: "num" }, { label: "Failed", className: "num" }, "Received", "Report ID"],
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
    reportDetailBody.replaceChildren(buildTable(
      ["Window", "Reporter", "Source IP", { label: "Count", className: "num" }, "Result", "SPF / DKIM", "Header From", "Envelope From", "Auth results", "Reasons"],
      recordRows(r.records || [], { showIp: true })
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
  const parts = [`${run.reports_added} added`];
  if (run.duplicates) parts.push(`${run.duplicates} duplicate${run.duplicates === 1 ? "" : "s"}`);
  if (run.errors) parts.push(`${run.errors} error${run.errors === 1 ? "" : "s"}`);
  return `${when} (${parts.join(", ")})`;
}

function renderSyncStatus(st) {
  const g = st.graph || {};
  graphConfig.replaceChildren(
    kvRow("Mailbox", g.mailbox || "not set"),
    kvRow("Folder", g.folder || "Inbox"),
    kvRow("Tenant", g.tenantId || "not set"),
    kvRow("Client ID", g.clientId || "not set"),
    kvRow("Scheduled sync", st.scheduler?.enabled ? `every ${st.scheduler.intervalMinutes} min` : "off"),
    kvRow("Backfill window", `${st.backfillDays} days on first sync`),
    kvRow("Last run", describeRun(st.lastRun)),
    kvRow("Stored", `${formatNumber(st.stats?.reports?.reports)} reports from ${formatNumber(st.stats?.messages?.ingested)} emails`)
  );

  if (!g.configured) {
    showSyncMessage(`Microsoft Graph is not configured. Set ${(g.missing || []).join(", ")} and restart. See the README for the Entra app registration steps.`, true);
    syncNowBtn.disabled = true;
    backfillBtn.disabled = true;
  } else {
    syncNowBtn.disabled = false;
    backfillBtn.disabled = false;
  }

  const runs = st.runs || [];
  runsResults.replaceChildren(buildTable(
    ["Started", "Trigger", { label: "Seen", className: "num" }, { label: "Added", className: "num" }, { label: "Duplicates", className: "num" }, { label: "Errors", className: "num" }, "Outcome"],
    runs.map((r) => ({
      data: r,
      cells: [
        textCell(formatTimestamp(r.started_at), "nowrap"),
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
  syncNowBtn.disabled = busy;
  backfillBtn.disabled = busy;
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
      if (job.status === "running") {
        syncPollTimer = setTimeout(poll, JOB_POLL_MS);
        return;
      }
      syncPollTimer = null;
      setSyncBusy(false);
      if (job.status === "failed") {
        showSyncMessage(`Sync failed: ${job.error}`, true);
      } else {
        showSyncMessage(`Sync finished: ${describeJob(job)}.${job.lastError ? ` Last problem: ${job.lastError}` : ""}`, job.errors > 0);
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

testGraphBtn.addEventListener("click", async () => {
  testGraphBtn.disabled = true;
  showSyncMessage("Testing the connection...");
  try {
    const result = await api("/api/graph/test", { method: "POST", body: "{}" });
    showSyncMessage(result.ok ? result.detail : `Connection test failed (${result.stage}): ${result.detail}`, !result.ok);
  } catch (error) {
    showSyncMessage(error.message, true);
  } finally {
    testGraphBtn.disabled = false;
  }
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
  testGraphBtn.hidden = !signedIn || user.role !== "admin";

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
  } catch (_) {
    // The dropdown is a convenience; the rest still loads.
  }
  await loadAll();
}

(async function init() {
  applyTheme(localStorage.getItem("dmarc-theme") || "light");
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
