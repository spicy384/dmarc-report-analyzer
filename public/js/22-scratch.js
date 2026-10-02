// 22-scratch.js: One-time analysis of uploaded files, never written to the database.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- one-time analysis ---------------------------------------------------------------
//
// The "Analyze files" page uploads into a scratch analysis on the server (an
// in-memory database that only this user can see). Opening it puts the dashboard
// into scratch mode: `scratchId` (01-core.js) makes every report-reading request go
// to /api/scratch/<id>/..., a banner says so, and anything that would write to the
// live store (labels, uploads, acknowledgements) is hidden.

const analyzeZone = document.getElementById("analyze-zone");
const analyzeInput = document.getElementById("analyze-input");
const analyzeResults = document.getElementById("analyze-results");
const analyzeStatus = document.getElementById("analyze-status");
const analyzeActions = document.getElementById("analyze-actions");
const analyzeBadge = document.getElementById("analyze-badge");
const scratchBanner = document.getElementById("scratch-banner");
const scratchSummary = document.getElementById("scratch-summary");
let scratchInfo = null;      // last /api/scratch/<id> status
let scratchUploading = false;
let scratchPreviousRange = null; // the period filter before the analysis widened it to "all time"

function describeScratch(info) {
  if (!info) return "";
  const bits = [`${formatNumber(info.files.length)} file${info.files.length === 1 ? "" : "s"}`];
  if (info.reports) bits.push(`${formatNumber(info.reports)} aggregate report${info.reports === 1 ? "" : "s"} (${formatNumber(info.messages)} messages)`);
  if (info.tls) bits.push(`${formatNumber(info.tls)} TLS report${info.tls === 1 ? "" : "s"}`);
  if (info.forensic) bits.push(`${formatNumber(info.forensic)} forensic report${info.forensic === 1 ? "" : "s"}`);
  if (info.domains && info.domains.length) bits.push(`domains: ${info.domains.join(", ")}`);
  return bits.join("; ");
}

function renderScratchChrome() {
  const on = Boolean(scratchId);
  document.body.classList.toggle("scratch-mode", on);
  scratchBanner.hidden = !on;
  if (on && scratchInfo) {
    scratchSummary.textContent = `${describeScratch(scratchInfo)}. Not saved; expires ${formatTimestamp(scratchInfo.expiresAt)} unless used.`;
  }
  analyzeActions.hidden = !scratchInfo || !(scratchInfo.reports || scratchInfo.tls || scratchInfo.forensic);
  analyzeBadge.textContent = scratchInfo ? describeScratch(scratchInfo) : "";
  if (on) mailboxSelect.value = "";
}

/** Uploads one file into the current analysis (creating it on the first file). */
async function scratchUploadOne(file) {
  const li = document.createElement("li");
  li.className = "upload-result";
  const name = document.createElement("strong");
  name.textContent = file.name;
  const outcome = document.createElement("span");
  outcome.textContent = " analysing...";
  li.append(name, outcome);
  analyzeResults.prepend(li);
  if (file.size > UPLOAD_MAX_BYTES) {
    outcome.textContent = ` skipped: ${Math.round(file.size / 1024 / 1024)} MB is over the 200 MB limit`;
    li.classList.add("is-fail");
    return null;
  }
  try {
    const target = scratchId ? `/api/scratch/${encodeURIComponent(scratchId)}/upload` : "/api/scratch/upload";
    const res = await fetch(target, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream", "X-File-Name": encodeURIComponent(file.name), "X-CSRF-Token": csrfToken || "" },
      body: file,
      credentials: "same-origin"
    });
    const body = await res.json().catch(() => ({}));
    if (res.status === 404 && scratchId) {
      // The analysis expired under us: start a fresh one with this file.
      scratchId = null;
      scratchInfo = null;
      return scratchUploadOne(file);
    }
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    scratchId = body.id;
    scratchInfo = body.analysis;
    outcome.textContent = ` ${describeUploadResult(body)}`;
    if (body.problems && body.problems.length) {
      li.classList.add(body.found ? "is-warn" : "is-fail");
      const ul = document.createElement("ul");
      ul.className = "upload-problems";
      for (const p of body.problems) {
        const item = document.createElement("li");
        item.textContent = p;
        ul.appendChild(item);
      }
      li.appendChild(ul);
    }
    return body;
  } catch (error) {
    outcome.textContent = ` failed: ${error.message}`;
    li.classList.add("is-fail");
    return null;
  }
}

async function scratchUploadFiles(files) {
  const list = [...files].filter((f) => f && f.size >= 0);
  if (!list.length || scratchUploading) return;
  scratchUploading = true;
  analyzeStatus.hidden = false;
  analyzeStatus.textContent = `Analysing ${list.length} file${list.length === 1 ? "" : "s"}...`;
  let added = 0;
  try {
    for (const file of list) {
      const r = await scratchUploadOne(file);
      if (r) added += r.aggregate.added + r.tls.added + r.forensic.added;
    }
  } finally {
    scratchUploading = false;
  }
  renderScratchChrome();
  if (added && scratchId) {
    analyzeStatus.textContent = `${formatNumber(added)} report${added === 1 ? "" : "s"} ready. Opening the analysis...`;
    await enterScratch(scratchId);
  } else {
    analyzeStatus.textContent = scratchId ? "Nothing new in those files; the analysis is unchanged." : "Nothing usable in those files.";
  }
}

/** Switches the dashboard to a scratch analysis and reloads every panel from it. */
async function enterScratch(id, { verify = false } = {}) {
  scratchId = id;
  if (verify || !scratchInfo) {
    try {
      scratchInfo = await api(`/api/scratch/${encodeURIComponent(id)}`);
    } catch (error) {
      scratchId = null;
      scratchInfo = null;
      renderScratchChrome();
      setStatus(error.status === 404 ? "That analysis has expired; upload the files again." : error.message, true);
      writeHash();
      return;
    }
  }
  renderScratchChrome();
  // The uploaded reports may cover any period; show them all rather than the last 30 days.
  if (scratchPreviousRange === null) {
    scratchPreviousRange = rangeSelect.value;
    rangeSelect.value = "all";
    fromLabel.hidden = true;
    toLabel.hidden = true;
  }
  domainSelect.value = "";
  await setView("dashboard");
  try {
    await loadDomains();
  } catch (_) { /* dropdown is a convenience */ }
  await loadAll();
}

/** Back to the live data (the analysis stays on the server until it expires, unless discarded). */
async function exitScratch({ reload = true, discard = false } = {}) {
  const id = scratchId;
  scratchId = null;
  if (discard && id) {
    api(`/api/scratch/${encodeURIComponent(id)}`, { method: "DELETE" }).catch(() => {});
    scratchInfo = null;
    analyzeResults.replaceChildren();
    analyzeStatus.hidden = true;
  }
  renderScratchChrome();
  if (scratchPreviousRange !== null) {
    if (rangeSelect.value === "all" && [...rangeSelect.options].some((o) => o.value === scratchPreviousRange)) rangeSelect.value = scratchPreviousRange;
    scratchPreviousRange = null;
    const custom = rangeSelect.value === "custom";
    fromLabel.hidden = !custom;
    toLabel.hidden = !custom;
  }
  domainSelect.value = "";
  if (!reload) return;
  try {
    await loadDomains();
    const status = await api("/api/status");
    populateMailboxSelect(status.mailboxes || [], status.mailboxCounts || []);
  } catch (_) { /* dropdowns are a convenience */ }
  await loadAll();
}

document.getElementById("scratch-add").addEventListener("click", () => setView("analyze"));
document.getElementById("scratch-exit").addEventListener("click", () => exitScratch());
document.getElementById("scratch-discard").addEventListener("click", () => exitScratch({ discard: true }));
document.getElementById("analyze-open").addEventListener("click", () => { if (scratchId) enterScratch(scratchId); });
document.getElementById("analyze-discard").addEventListener("click", () => exitScratch({ discard: true, reload: currentView === "dashboard" }));

analyzeZone.addEventListener("click", () => analyzeInput.click());
analyzeZone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    analyzeInput.click();
  }
});
analyzeInput.addEventListener("change", () => {
  scratchUploadFiles(analyzeInput.files);
  analyzeInput.value = "";
});
for (const type of ["dragenter", "dragover"]) {
  analyzeZone.addEventListener(type, (e) => {
    e.preventDefault();
    analyzeZone.classList.add("is-over");
  });
}
for (const type of ["dragleave", "drop"]) {
  analyzeZone.addEventListener(type, (e) => {
    e.preventDefault();
    analyzeZone.classList.remove("is-over");
  });
}
analyzeZone.addEventListener("drop", (e) => {
  if (e.dataTransfer && e.dataTransfer.files) scratchUploadFiles(e.dataTransfer.files);
});
