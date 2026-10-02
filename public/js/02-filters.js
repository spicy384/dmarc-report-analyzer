// 02-filters.js: Period, domain, mailbox and search filters; the filter query string.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

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
  a.href = apiPath(`/api/export/records.csv${filterQuery()}`);
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
  populatePolicyDomains(data.domains || []);
}
