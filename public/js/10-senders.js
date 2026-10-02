// 10-senders.js: Known senders and the SPF import.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

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

const ksSuggestion = document.getElementById("ks-suggestion");

/**
 * Shows what the catalogue or the reverse DNS suggests for the source being
 * labelled, with a button that fills the form from it. `suggestion` is
 * { pattern, kind, label, reason }.
 */
function showSenderSuggestion(suggestion) {
  ksSuggestion.replaceChildren();
  ksSuggestion.hidden = !suggestion;
  if (!suggestion) return;
  const text = document.createElement("span");
  text.textContent = `${suggestion.reason} Suggested: label "${suggestion.label}" as ${KIND_LABEL[suggestion.kind] || suggestion.kind} with pattern `;
  const code = document.createElement("code");
  code.className = "mono";
  code.textContent = suggestion.pattern;
  const use = document.createElement("button");
  use.type = "button";
  use.className = "link-btn";
  use.textContent = "Use this";
  use.addEventListener("click", () => {
    ksPattern.value = suggestion.pattern;
    ksKind.value = suggestion.kind;
    ksLabel.value = suggestion.label;
    ksLabel.focus();
  });
  ksSuggestion.append(text, code, ". ", use);
}

function openSenderForm(prefill, { suggestion = null } = {}) {
  editingSenderId = prefill && prefill.id ? prefill.id : null;
  ksPattern.value = prefill ? prefill.pattern || "" : "";
  ksKind.value = prefill && prefill.kind ? prefill.kind : "ours";
  ksLabel.value = prefill ? prefill.label || "" : "";
  ksNote.value = prefill ? prefill.note || "" : "";
  ksSave.textContent = editingSenderId ? "Save" : "Add";
  ksCancel.hidden = !editingSenderId && !prefill;
  showSenderSuggestion(suggestion);
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
  showSenderSuggestion(null);
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
