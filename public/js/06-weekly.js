// 06-weekly.js: This-week summary with tabs and copy-as-text.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- weekly summary -----------------------------------------------------------

const weeklyEnd = document.getElementById("weekly-end");
const weeklyBody = document.getElementById("weekly-body");
const weeklyBadge = document.getElementById("weekly-badge");
const weeklyTabState = { tab: "totals" };
let weeklyData = null;

function shiftWeek(days) {
  const base = weeklyEnd.value ? Date.parse(`${weeklyEnd.value}T00:00:00Z`) / 1000 : todayUtcStart();
  weeklyEnd.value = formatUtcDate(base + days * DAY);
  loadWeekly();
}

document.getElementById("weekly-prev").addEventListener("click", () => shiftWeek(-7));
document.getElementById("weekly-next").addEventListener("click", () => shiftWeek(7));
weeklyEnd.addEventListener("change", () => loadWeekly());

document.getElementById("weekly-copy").addEventListener("click", async () => {
  if (!weeklyData) return;
  if (await copyToClipboard(weeklyData.text)) {
    setStatus("Weekly summary copied to the clipboard.");
  } else {
    setStatus("Could not copy; select the text below and copy it yourself.", true);
    const pre = document.createElement("pre");
    pre.className = "exo-code mono";
    pre.textContent = weeklyData.text;
    weeklyBody.prepend(pre);
  }
});

function weeklyChange(cur, prev, { pct = false, upIsGood = null } = {}) {
  const diff = (cur || 0) - (prev || 0);
  const span = document.createElement("span");
  if (Math.abs(diff) < (pct ? 0.05 : 0.5)) {
    span.className = "weekly-change";
    span.textContent = "unchanged";
    return span;
  }
  const up = diff > 0;
  span.className = `weekly-change${upIsGood === null ? "" : up === upIsGood ? " is-good" : " is-bad"}`;
  span.textContent = pct
    ? `${up ? "▲" : "▼"} ${Math.abs(diff).toFixed(1)} pts`
    : `${up ? "▲" : "▼"} ${prev ? Math.round((Math.abs(diff) / prev) * 100) + "%" : formatNumber(Math.abs(diff))}`;
  return span;
}

function renderWeekly(w) {
  weeklyData = w;
  const t = w.thisWeek.totals;
  const p = w.lastWeek.totals;
  weeklyBadge.textContent = `${formatUtcDate(w.thisWeek.from)} to ${formatUtcDate(w.thisWeek.to - 1)}`;
  weeklyBody.replaceChildren();

  const metrics = [
    ["Messages", formatNumber(t.messages), formatNumber(p.messages), weeklyChange(t.messages, p.messages)],
    ["DMARC pass rate", formatPct(t.passPct), formatPct(p.passPct), weeklyChange(t.passPct, p.passPct, { pct: true, upIsGood: true })],
    ["Failures", formatNumber(t.failed), formatNumber(p.failed), weeklyChange(t.failed, p.failed, { upIsGood: false })],
    ["  of which likely forwards", formatNumber(t.likelyForwards), formatNumber(p.likelyForwards), weeklyChange(t.likelyForwards, p.likelyForwards)],
    ["Quarantined", formatNumber(t.quarantined), formatNumber(p.quarantined), weeklyChange(t.quarantined, p.quarantined, { upIsGood: false })],
    ["Rejected", formatNumber(t.rejected), formatNumber(p.rejected), weeklyChange(t.rejected, p.rejected, { upIsGood: false })],
    ["Failing sources", formatNumber(t.failingIps), formatNumber(p.failingIps), weeklyChange(t.failingIps, p.failingIps, { upIsGood: false })],
    ["Reports received", formatNumber(t.reports), formatNumber(p.reports), weeklyChange(t.reports, p.reports)],
    ["Reporting services", formatNumber(t.reporters), formatNumber(p.reporters), weeklyChange(t.reporters, p.reporters)]
  ];
  const table = buildTable(
    ["", { label: "This week", className: "num" }, { label: "Last week", className: "num" }, "Change"],
    metrics.map(([label, cur, prev, change]) => ({
      data: null,
      cells: [textCell(label, label.startsWith("  ") ? "muted" : ""), textCell(cur, "num"), textCell(prev, "num muted"), (() => { const td = document.createElement("td"); td.appendChild(change); return td; })()]
    }))
  );
  // One tab per section: the two-column layout squeezed the table and the lists.
  const totalsBox = policyBox("Totals");
  const scroll = document.createElement("div");
  scroll.className = "table-scroll";
  scroll.appendChild(table);
  totalsBox.appendChild(scroll);
  const tabs = [{ key: "totals", label: "Totals", box: totalsBox }];

  const section = (key, title, rows, render) => {
    const box = policyBox(title, { badge: String(rows.length) });
    if (!rows.length) {
      const none = document.createElement("p");
      none.className = "empty-state small";
      none.textContent = "None this week.";
      box.appendChild(none);
    } else {
      const ul = document.createElement("ul");
      ul.className = "weekly-list";
      for (const r of rows) {
        const li = document.createElement("li");
        render(li, r);
        ul.appendChild(li);
      }
      box.appendChild(ul);
    }
    tabs.push({ key, label: title, box });
  };
  const ipLine = (li, r, what) => {
    const a = document.createElement("a");
    a.href = "#";
    a.className = "mono";
    a.textContent = r.ip;
    a.addEventListener("click", (e) => { e.preventDefault(); openIpDetail(r.ip); });
    li.appendChild(a);
    li.append(` ${what}${r.sender ? ` - ${r.sender.label}` : r.ptr ? ` - ${r.ptr}` : r.asOrg ? ` - ${r.asOrg}` : ""}`);
  };
  section("new", "New sources", w.newSources, (li, r) => ipLine(li, r, `${formatNumber(r.failed)} of ${formatNumber(r.total)} failed`));
  section("failing", "Top failing sources", w.topFailing, (li, r) => ipLine(li, r, `${formatNumber(r.failed)} failed of ${formatNumber(r.total)}${r.likelyForwards ? ` (${formatNumber(r.likelyForwards)} likely forwards)` : ""}`));
  section("forwards", "Top forwarders", w.topForwards, (li, r) => ipLine(li, r, `${formatNumber(r.likelyForwards)} likely forwards`));
  section("reporters", "Reporting services", w.thisWeek.reporters, (li, r) => { li.textContent = `${r.orgName}: ${formatNumber(r.reports)} reports, ${formatNumber(r.messages)} messages, ${formatPct(r.failPct)} failed`; });
  policyTabs(tabs, weeklyBody, weeklyTabState);
}

async function loadWeekly() {
  if (!weeklyEnd.value) {
    weeklyEnd.value = formatUtcDate(todayUtcStart());
  }
  const params = new URLSearchParams({ end: weeklyEnd.value });
  if (domainSelect.value) params.set("domain", domainSelect.value);
  if (mailboxSelect.value) params.set("mailbox", mailboxSelect.value);
  const data = await api(`/api/weekly?${params}`);
  renderWeekly(data);
}
