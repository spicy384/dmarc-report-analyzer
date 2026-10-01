// 03-overview.js: Overview tiles, deltas against the previous period, the daily chart.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- overview --------------------------------------------------------------

function statTile(label, value, { sub = "", tone = "", small = false, delta = null } = {}) {
  const div = document.createElement("div");
  div.className = `stat${tone ? " stat-" + tone : ""}${small ? " stat-small" : ""}`;
  const v = document.createElement("div");
  v.className = "stat-value";
  v.textContent = value;
  if (delta) {
    const d = document.createElement("span");
    d.className = `stat-delta ${delta.direction}${delta.good === null ? "" : delta.good ? " is-good" : " is-bad"}`;
    d.textContent = delta.text;
    d.title = delta.title;
    v.appendChild(d);
  }
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
let previousTotals = null;
let previousLabel = "";

/**
 * A change against the previous period. `kind` is "count" or "pct" (percentage points);
 * `upIsGood` says which direction to colour green (null: neutral).
 */
function delta(current, previous, { kind = "count", upIsGood = null } = {}) {
  if (!previousTotals || previous === undefined || previous === null) return null;
  const diff = (current || 0) - (previous || 0);
  if (Math.abs(diff) < (kind === "pct" ? 0.05 : 0.5)) {
    return { direction: "flat", text: "=", good: null, title: `Unchanged against the ${previousLabel}` };
  }
  const up = diff > 0;
  const arrow = up ? "\u25B2" : "\u25BC";
  const text = kind === "pct"
    ? `${arrow} ${Math.abs(diff).toFixed(1)} pts`
    : `${arrow} ${previous ? Math.round((Math.abs(diff) / previous) * 100) + "%" : formatNumber(Math.abs(diff))}`;
  const good = upIsGood === null ? null : up === upIsGood;
  return { direction: up ? "up" : "down", text, good, title: `${previousLabel}: ${kind === "pct" ? formatPct(previous) : formatNumber(previous)}` };
}

function renderStats(t) {
  const p = previousTotals || {};
  statGrid.replaceChildren(
    statTile("Messages", formatNumber(t.messages), { sub: `${formatNumber(t.reports)} reports`, delta: delta(t.messages, p.messages) }),
    statTile("DMARC pass", formatPct(t.passPct), { sub: `${formatNumber(t.passed)} messages`, tone: "pass", delta: delta(t.passPct, p.passPct, { kind: "pct", upIsGood: true }) }),
    statTile("DMARC fail", formatPct(t.failPct), {
      sub: `${formatNumber(t.failed)} messages${t.likelyForwards ? `, ${formatNumber(t.likelyForwards)} likely forwards` : ""}`,
      tone: t.failed > 0 ? "fail" : "",
      delta: delta(t.failPct, p.failPct, { kind: "pct", upIsGood: false })
    }),
    statTile("Quarantined", formatNumber(t.quarantined), { tone: t.quarantined > 0 ? "quarantine" : "", delta: delta(t.quarantined, p.quarantined, { upIsGood: false }) }),
    statTile("Rejected", formatNumber(t.rejected), { tone: t.rejected > 0 ? "reject" : "", delta: delta(t.rejected, p.rejected, { upIsGood: false }) }),
    statTile("Failing sources", formatNumber(t.failingIps), { sub: `of ${formatNumber(t.sourceIps)} source IPs`, delta: delta(t.failingIps, p.failingIps, { upIsGood: false }) }),
    senderTile(t),
    statTile("Reporters", formatNumber(t.reporters), { sub: t.domains > 1 ? `${t.domains} domains` : "", delta: delta(t.reporters, p.reporters) }),
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
    hit.style.cursor = d.total > 0 ? "pointer" : "default";
    hit.addEventListener("mouseenter", () => showTip(d, margin.left + i * slot + slot / 2));
    hit.addEventListener("mouseleave", () => { chartTip.hidden = true; });
    // Clicking a day narrows the whole dashboard to it.
    hit.addEventListener("click", () => {
      if (d.total <= 0) return;
      rangeSelect.value = "custom";
      fromDate.value = d.day;
      toDate.value = d.day;
      chartTip.hidden = true;
      onRangeChanged();
    });
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
    if (d.total > 0) {
      const click = document.createElement("div");
      click.className = "chart-tip-hint";
      click.textContent = "Click to show only this day";
      chartTip.appendChild(click);
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

/** The window of equal length just before the current one, or null for open-ended ranges. */
function previousRange() {
  const { from, to } = currentRange();
  if (from === null || to === null) return null;
  const length = to - from;
  return { from: from - length, to: from, days: Math.round(length / DAY) };
}

async function loadSummary() {
  const prev = previousRange();
  const [data, prevData] = await Promise.all([
    api(`/api/summary${filterQuery()}`),
    prev ? api(`/api/summary${filterQuery({ from: prev.from, to: prev.to })}`).catch(() => null) : Promise.resolve(null)
  ]);
  previousTotals = prevData ? prevData.totals : null;
  previousLabel = prev ? `previous ${prev.days} days (${formatUtcDate(prev.from)} to ${formatUtcDate(prev.to - 1)})` : "";
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
