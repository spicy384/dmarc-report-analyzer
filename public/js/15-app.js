// 15-app.js: loadAll() and deep links in the page hash.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- load everything -------------------------------------------------------

// --- deep links ------------------------------------------------------------------

let applyingHash = false;
let pendingOpen = null;
let openIp = null;
let openReport = null;

/** Reads filter state from the URL fragment (#range=30&domain=...&q=...&hide=1&ip=...&report=...). */
let loadGeneration = 0;
let activeLoadController = null;

/**
 * Restores filter state from the page link. With `sideEffects` off (before sign-in)
 * it only fills the controls; lookups, analyses and the view switch wait for onSignedIn.
 */
function readHash({ sideEffects = true } = {}) {
  const raw = location.hash.replace(/^#/, "");
  if (!raw) return false;
  const p = new URLSearchParams(raw);
  if (p.has("range") && [...rangeSelect.options].some((o) => o.value === p.get("range"))) rangeSelect.value = p.get("range");
  if (p.has("from")) fromDate.value = p.get("from");
  if (p.has("to")) toDate.value = p.get("to");
  if (p.has("domain")) domainSelect.value = p.get("domain");
  if (p.has("mailbox")) mailboxSelect.value = p.get("mailbox");
  searchInput.value = p.get("q") || "";
  hideForwards.checked = p.get("hide") === "1";
  if (p.has("failing")) failingOnly.checked = p.get("failing") !== "0";
  pendingOpen = p.has("ip") ? { ip: p.get("ip") } : p.has("report") ? { report: p.get("report") } : null;
  const view = Object.hasOwn(VIEWS, p.get("view") || "") ? p.get("view") : "dashboard";
  // The view switch must not rewrite the link: the domain and mailbox in it are only
  // applied once their dropdowns are filled, after sign-in.
  if (view !== currentView) setView(view, { keepHash: true });
  if (sideEffects) {
    // A one-time analysis survives a reload while the server still has it.
    const scratch = p.get("scratch") || null;
    if (scratch !== scratchId) {
      if (scratch) run(() => enterScratch(scratch, { verify: true }));
      else exitScratch({ reload: false });
    }
    const wanted = p.get("lookup") || "";
    if (wanted && wanted !== lookupQuery) {
      lookupInput.value = wanted;
      run(runLookup);
    }
  }
  const custom = rangeSelect.value === "custom";
  fromLabel.hidden = !custom;
  toLabel.hidden = !custom;
  return true;
}

function writeHash(extra = {}) {
  const p = new URLSearchParams();
  p.set("range", rangeSelect.value);
  if (rangeSelect.value === "custom") {
    if (fromDate.value) p.set("from", fromDate.value);
    if (toDate.value) p.set("to", toDate.value);
  }
  if (domainSelect.value) p.set("domain", domainSelect.value);
  if (mailboxSelect.value) p.set("mailbox", mailboxSelect.value);
  if (searchInput.value.trim()) p.set("q", searchInput.value.trim());
  if (hideForwards.checked) p.set("hide", "1");
  if (!failingOnly.checked) p.set("failing", "0");
  if (lookupQuery) p.set("lookup", lookupQuery);
  if (currentView !== "dashboard") p.set("view", currentView);
  if (scratchId) p.set("scratch", scratchId);
  for (const [k, v] of Object.entries(extra)) {
    if (v !== null && v !== undefined && v !== "") p.set(k, String(v));
  }
  applyingHash = true;
  history.replaceState(null, "", `#${p.toString()}`);
  applyingHash = false;
}

window.addEventListener("hashchange", () => {
  if (applyingHash) return;
  if (readHash()) {
    reportsPage = 1;
    loadAll();
  }
});

async function loadAll() {
  // A newer load supersedes this one: its requests are aborted and its results ignored.
  if (activeLoadController) activeLoadController.abort();
  activeLoadController = new AbortController();
  activeLoadSignal = activeLoadController.signal;
  const generation = ++loadGeneration;
  const range = currentRange();
  rangeLabel.textContent = range.label + (domainSelect.value ? ` - ${domainSelect.value}` : "");
  if (domainSelect.value && policyDomain.value !== domainSelect.value) policyDomain.value = domainSelect.value;
  setStatus("Loading...");
  renderFilterChips();
  const tasks = [
    ["summary", loadSummary],
    ["sources", loadIps],
    ["reporters", loadReporters],
    ["subdomains", loadSubdomains],
    ["scorecard", loadScorecard],
    ["known senders", loadKnownSenders],
    ["alerts", loadAlerts],
    ["policy", loadPolicy],
    ["weekly", loadWeekly],
    ["forensic", loadForensic],
    ["tls", loadTls],
    ["reports", loadReports],
    ["sync status", loadSyncStatus]
  ];
  const problems = [];
  await Promise.all(tasks.map(async ([name, fn]) => {
    try {
      await fn();
    } catch (error) {
      if (error && error.name !== "AbortError") problems.push(`${name}: ${error.message}`);
    }
  }));
  if (generation !== loadGeneration) return;
  if (problems.length) {
    setStatus(problems.join(" | "), true);
  } else {
    setStatus(`Updated ${formatTimestamp(Math.floor(Date.now() / 1000))}`);
  }
  writeHash(openIp ? { ip: openIp } : openReport ? { report: openReport } : {});
  if (pendingOpen) {
    const open = pendingOpen;
    pendingOpen = null;
    if (open.ip) openIpDetail(open.ip);
    else if (open.report) openReportDetail(open.report);
  }
}
