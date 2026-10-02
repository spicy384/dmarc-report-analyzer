// 21-upload.js: Manual upload of report files.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- manual upload ----------------------------------------------------------------
//
// Files go up one at a time as raw bodies (no multipart), so a 100 MB zip of a
// year's reports does not have to be held in memory twice. Each result is listed
// as it comes back; the dashboard reloads once at the end.

const uploadZone = document.getElementById("upload-zone");
const uploadInput = document.getElementById("upload-input");
const uploadResults = document.getElementById("upload-results");
const uploadStatus = document.getElementById("upload-status");
const UPLOAD_MAX_BYTES = 200 * 1024 * 1024;

function describeUploadResult(r) {
  const bits = [];
  if (r.aggregate.added) bits.push(`${formatNumber(r.aggregate.added)} aggregate report${r.aggregate.added === 1 ? "" : "s"} added`);
  if (r.tls.added) bits.push(`${formatNumber(r.tls.added)} TLS report${r.tls.added === 1 ? "" : "s"} added`);
  if (r.forensic.added) bits.push(`${formatNumber(r.forensic.added)} forensic report${r.forensic.added === 1 ? "" : "s"} added`);
  const dups = r.aggregate.duplicates + r.tls.duplicates + r.forensic.duplicates;
  if (dups) bits.push(`${formatNumber(dups)} already stored`);
  return bits.join(", ") || "nothing stored";
}

async function uploadOne(file) {
  const li = document.createElement("li");
  li.className = "upload-result";
  const name = document.createElement("strong");
  name.textContent = file.name;
  const outcome = document.createElement("span");
  outcome.textContent = " uploading...";
  li.append(name, outcome);
  uploadResults.prepend(li);
  if (file.size > UPLOAD_MAX_BYTES) {
    outcome.textContent = ` skipped: ${Math.round(file.size / 1024 / 1024)} MB is over the 200 MB limit`;
    li.classList.add("is-fail");
    return null;
  }
  try {
    const res = await fetch("/api/upload", {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream", "X-File-Name": encodeURIComponent(file.name), "X-CSRF-Token": csrfToken || "" },
      body: file,
      credentials: "same-origin"
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
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

async function uploadFiles(files) {
  const list = [...files].filter((f) => f && f.size >= 0);
  if (!list.length) return;
  uploadStatus.hidden = false;
  uploadStatus.textContent = `Uploading ${list.length} file${list.length === 1 ? "" : "s"}...`;
  let added = 0;
  for (const file of list) {
    const r = await uploadOne(file);
    if (r) added += r.aggregate.added + r.tls.added + r.forensic.added;
  }
  uploadStatus.textContent = added ? `Done: ${formatNumber(added)} report${added === 1 ? "" : "s"} added. Refreshing...` : "Done: nothing new was stored.";
  if (added) {
    try {
      await loadDomains();
      const status = await api("/api/status");
      populateMailboxSelect(status.mailboxes || [], status.mailboxCounts || []);
    } catch (_) { /* dropdowns are a convenience */ }
    await loadAll();
    uploadStatus.textContent = `Done: ${formatNumber(added)} report${added === 1 ? "" : "s"} added.`;
  }
}

uploadZone.addEventListener("click", () => uploadInput.click());
uploadZone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    uploadInput.click();
  }
});
uploadInput.addEventListener("change", () => {
  uploadFiles(uploadInput.files);
  uploadInput.value = "";
});
for (const type of ["dragenter", "dragover"]) {
  uploadZone.addEventListener(type, (e) => {
    e.preventDefault();
    uploadZone.classList.add("is-over");
  });
}
for (const type of ["dragleave", "drop"]) {
  uploadZone.addEventListener(type, (e) => {
    e.preventDefault();
    uploadZone.classList.remove("is-over");
  });
}
uploadZone.addEventListener("drop", (e) => {
  if (e.dataTransfer && e.dataTransfer.files) uploadFiles(e.dataTransfer.files);
});
