// 14-mailboxes.js: Mailbox sync status, source types, the mailbox form.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

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
  // Manually uploaded files sit under their own pseudo-mailbox.
  for (const c of counts || []) {
    if (c.id === "upload") mailboxNames.set(c.id, "Manual uploads");
    else if (!known.has(c.id)) mailboxNames.set(c.id, `${c.id} (removed)`);
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

// --- mailbox source types ------------------------------------------------------
//
// Microsoft 365 keeps its own fields in the markup (it has the secret / certificate
// choice). The other types are plain lists of fields, rendered from these definitions
// into both the mailbox form and the setup walkthrough so the two cannot drift apart.

const SECURITY_OPTIONS = [["tls", "TLS (implicit)"], ["starttls", "STARTTLS"], ["none", "None (unencrypted)"]];

const SOURCE_TYPES = {
  graph: { label: "Microsoft 365" },
  gws: {
    label: "Google Workspace",
    intro: "Uses a Google Cloud service account with domain-wide delegation for the read-only Gmail scope, so it keeps working unattended. The service account reads the mailbox as the user below.",
    fields: [
      { key: "mailbox", label: "Mailbox address (the user to read)", placeholder: "dmarc-reports@example.com", required: true, mono: true },
      { key: "folder", label: "Label (optional)", placeholder: "DMARC", hint: "Only messages with this Gmail label. Leave empty to read the whole mailbox." },
      { key: "serviceAccountKey", label: "Service account key (JSON)", kind: "textarea", secret: true, required: true, placeholder: "{ \"type\": \"service_account\", \"client_email\": \"...\", \"private_key\": \"...\" }" }
    ]
  },
  ses: {
    label: "Amazon SES",
    intro: "SES delivers inbound mail to an S3 bucket through a receipt rule; this reads those objects. The access key needs s3:ListBucket on the bucket and s3:GetObject on its objects.",
    fields: [
      { key: "region", label: "Region", placeholder: "us-east-1", required: true, mono: true },
      { key: "bucket", label: "Bucket", placeholder: "my-ses-inbound", required: true, mono: true },
      { key: "prefix", label: "Key prefix (optional)", placeholder: "dmarc/", mono: true, hint: "The object key prefix set on the receipt rule's S3 action, if any." },
      { key: "accessKeyId", label: "Access key ID", placeholder: "AKIA...", required: true, mono: true },
      { key: "secretAccessKey", label: "Secret access key", kind: "password", secret: true, required: true },
      { key: "endpoint", label: "Endpoint (optional)", placeholder: "https://s3.example.internal", mono: true, hint: "Only for S3-compatible storage; leave empty for AWS." }
    ]
  },
  imap: {
    label: "IMAP",
    intro: "Any mail server with IMAP. The folder is opened read-only, so nothing is marked as read or moved. Use an app password if the account has two-factor turned on.",
    fields: [
      { key: "host", label: "Server", placeholder: "imap.example.com", required: true, mono: true },
      { key: "security", label: "Security", kind: "select", options: SECURITY_OPTIONS, default: "tls" },
      { key: "port", label: "Port (optional)", placeholder: "993 for TLS, 143 otherwise", mono: true },
      { key: "username", label: "Username", placeholder: "dmarc-reports@example.com", required: true, mono: true },
      { key: "password", label: "Password", kind: "password", secret: true, required: true },
      { key: "folder", label: "Folder", placeholder: "INBOX", default: "INBOX" },
      { key: "tlsVerify", label: "Check the server's TLS certificate", kind: "checkbox", default: true }
    ]
  },
  pop3: {
    label: "POP3",
    intro: "Any mail server with POP3. Messages are downloaded, never deleted. POP3 has no folders or dates in its listing, so every message not seen before is fetched once whatever its age.",
    fields: [
      { key: "host", label: "Server", placeholder: "pop.example.com", required: true, mono: true },
      { key: "security", label: "Security", kind: "select", options: SECURITY_OPTIONS, default: "tls" },
      { key: "port", label: "Port (optional)", placeholder: "995 for TLS, 110 otherwise", mono: true },
      { key: "username", label: "Username", placeholder: "dmarc-reports@example.com", required: true, mono: true },
      { key: "password", label: "Password", kind: "password", secret: true, required: true },
      { key: "tlsVerify", label: "Check the server's TLS certificate", kind: "checkbox", default: true }
    ]
  }
};

/** Builds the inputs for a non-Graph type inside `container`; ids are `${prefix}-${key}`. */
function renderSourceFields(container, type, prefix, existing = null) {
  container.replaceChildren();
  const def = SOURCE_TYPES[type];
  if (!def || !def.fields) return;
  for (const f of def.fields) {
    const id = `${prefix}-${f.key}`;
    const label = document.createElement("label");
    let input;
    if (f.kind === "checkbox") {
      label.className = "check-inline";
      input = document.createElement("input");
      input.type = "checkbox";
      input.checked = existing && existing[f.key] !== undefined ? Boolean(existing[f.key]) : f.default !== false;
      label.append(input, ` ${f.label}`);
    } else {
      label.append(`${f.label} `);
      if (f.kind === "select") {
        input = document.createElement("select");
        for (const [value, text] of f.options) {
          const opt = document.createElement("option");
          opt.value = value;
          opt.textContent = text;
          input.appendChild(opt);
        }
        input.value = (existing && existing[f.key]) || f.default || f.options[0][0];
      } else if (f.kind === "textarea") {
        input = document.createElement("textarea");
        input.rows = 5;
        input.spellcheck = false;
      } else {
        input = document.createElement("input");
        if (f.kind === "password") {
          input.type = "password";
          input.autocomplete = "new-password";
        } else {
          input.autocomplete = "off";
        }
      }
      if (f.mono || f.kind === "textarea" || f.kind === "password") input.classList.add("mono");
      if (f.kind !== "select") {
        // Secrets are never sent back by the server; an empty box on an edit keeps the stored one.
        input.placeholder = f.secret && existing ? "leave blank to keep the current one" : (f.placeholder || "");
        input.value = f.secret ? "" : existing && existing[f.key] !== undefined && existing[f.key] !== null ? String(existing[f.key]) : (existing ? "" : (f.default && f.kind !== "checkbox" ? String(f.default) : ""));
      }
      label.appendChild(input);
    }
    input.id = id;
    if (f.kind === "textarea") label.classList.add("source-wide");
    container.appendChild(label);
    if (f.hint) {
      const hint = document.createElement("p");
      hint.className = "bulk-hint source-hint";
      hint.textContent = f.hint;
      container.appendChild(hint);
    }
  }
}

function collectSourceFields(type, prefix) {
  const out = {};
  for (const f of (SOURCE_TYPES[type] && SOURCE_TYPES[type].fields) || []) {
    const el = document.getElementById(`${prefix}-${f.key}`);
    if (!el) continue;
    out[f.key] = f.kind === "checkbox" ? el.checked : f.secret ? el.value : el.value.trim();
  }
  return out;
}

/** The first required field left empty, as a sentence; null when all are filled. Secrets may be empty on an edit. */
function sourceFieldProblem(type, values, { editing = false } = {}) {
  for (const f of (SOURCE_TYPES[type] && SOURCE_TYPES[type].fields) || []) {
    if (f.required && !values[f.key] && !(editing && f.secret)) return `Enter the ${f.label.replace(/ \(.*\)$/, "").toLowerCase()}.`;
  }
  return null;
}

/** What identifies the account behind a mailbox, per type, for the table. */
function describeMailboxAccount(m) {
  if (m.type === "imap" || m.type === "pop3") return `${m.username} at ${m.host}:${m.port}`;
  if (m.type === "gws") return m.serviceAccount || "service account";
  if (m.type === "ses") return `${m.bucket}/${m.prefix || ""} (${m.region})`;
  return m.tenantId || "";
}

/** "secret" or the certificate's thumbprint and expiry, flagged when it is expired or broken. */
function describeMailboxAuth(m) {
  if (m.type && m.type !== "graph") {
    const td = textCell(m.credentialError ? `${m.authMethod}: ${m.credentialError}` : m.authMethod || "", m.credentialError ? "trunc-wide is-fail" : "muted");
    return td;
  }
  if (m.authMethod !== "certificate") return textCell("secret", "muted");
  const c = m.certificate;
  if (!c || c.error) {
    const td = textCell(`certificate: ${c && c.error ? c.error : "unreadable"}`, "trunc-wide is-fail");
    td.title = c && c.error ? c.error : "";
    return td;
  }
  const soon = c.notAfter && c.notAfter - Date.now() / 1000 < 30 * DAY;
  const td = textCell(`certificate ${c.thumbprint.slice(0, 8)}… ${c.expired ? "expired" : "expires"} ${formatUtcDate(c.notAfter)}`, c.expired ? "trunc-wide is-fail" : soon ? "trunc-wide is-warn" : "trunc-wide muted");
  td.title = `${c.subject || ""}\nThumbprint ${c.thumbprint}`;
  return td;
}

function renderMailboxes(list) {
  mailboxList = list;
  const admin = isAdmin();
  mailboxesResults.replaceChildren(buildTable(
    ["Name", "Type", "Mailbox", "Folder", "Account", "Auth", "Last sync", { label: "Reports", className: "num" }, "State", ""],
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
          textCell(m.typeLabel || "Microsoft 365", "nowrap muted"),
          textCell(m.mailbox, "mono"),
          textCell(m.type === "pop3" || m.type === "ses" ? "" : m.folder || (m.type === "gws" ? "all mail" : "Inbox")),
          textCell(describeMailboxAccount(m), "mono muted trunc"),
          describeMailboxAuth(m),
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

function renderRetentionNote(rt) {
  if (!rt || !rt.enabled || !rt.purgedReports) {
    retentionNote.hidden = true;
    return;
  }
  const { from } = currentRange();
  const earliest = rt.earliestRetained || rt.cutoff;
  if (from !== null && from >= earliest) {
    retentionNote.hidden = true;
    return;
  }
  retentionNote.hidden = false;
  retentionNote.textContent = `Reports older than ${rt.months} month${rt.months === 1 ? "" : "s"} have been rolled up: totals and the chart include them, but sources, records, search and XML downloads only cover data since ${formatUtcDate(earliest)} (${formatNumber(rt.purgedReports)} reports rolled up).`;
}

function renderSyncStatus(st) {
  const list = st.mailboxes || [];
  renderRetentionNote(st.retention);
  populateMailboxSelect(list, st.mailboxCounts || []);
  renderMailboxes(list);

  graphConfig.replaceChildren(
    kvRow("Scheduled sync", st.scheduler?.enabled ? `every ${st.scheduler.intervalMinutes} min` : "off"),
    kvRow("Backfill window", `${st.backfillDays} days on a mailbox's first sync`),
    kvRow("Last run", describeRun(st.lastRun)),
    kvRow("Stored", `${formatNumber(st.stats?.reports?.reports)} reports from ${formatNumber(st.stats?.messages?.ingested)} emails`),
    kvRow("GeoIP", describeGeoip(st.geoip)),
    kvRow("Retention", st.retention && st.retention.enabled ? `${st.retention.months} month${st.retention.months === 1 ? "" : "s"}; ${formatNumber(st.retention.purgedReports)} reports rolled up into ${formatNumber(st.retention.rolledUpDays)} daily totals` : "keeping everything")
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

/** Shows the Microsoft 365 fields or the generated ones for another type. */
function setMailboxType(type, existing = null) {
  const graph = type === "graph";
  document.getElementById("mb-type").value = type;
  mailboxForm.querySelectorAll(".mb-graph-only").forEach((el) => { el.hidden = !graph; });
  const other = document.getElementById("mb-other");
  const intro = document.getElementById("mb-type-intro");
  other.hidden = graph;
  intro.hidden = graph || !SOURCE_TYPES[type].intro;
  intro.textContent = graph ? "" : SOURCE_TYPES[type].intro || "";
  renderSourceFields(other, type, "mbf", existing);
}

document.getElementById("mb-type").addEventListener("change", (event) => setMailboxType(event.target.value));

function openMailboxForm(m) {
  editingMailboxId = m ? m.id : null;
  mailboxFormTitle.textContent = m ? `Edit ${m.name}` : "Add a mailbox";
  // A mailbox keeps its type; to change it, add a new one.
  document.getElementById("mb-type").disabled = Boolean(m);
  setMailboxType(m ? m.type || "graph" : "graph", m);
  document.getElementById("mb-name").value = m ? m.name : "";
  document.getElementById("mb-tenant").value = m ? m.tenantId : "";
  document.getElementById("mb-client").value = m ? m.clientId : "";
  document.getElementById("mb-secret").value = "";
  document.getElementById("mb-secret").placeholder = m && m.hasSecret ? "leave blank to keep the current secret" : "";
  document.getElementById("mb-cert").value = "";
  document.getElementById("mb-cert").placeholder = m && m.hasCertificate
    ? `leave blank to keep the current certificate (${m.certificate && m.certificate.thumbprint ? `thumbprint ${m.certificate.thumbprint}` : "stored"})`
    : "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
  document.getElementById("mb-key").value = "";
  document.getElementById("mb-key").placeholder = m && m.hasCertificate ? "leave blank to keep the current key" : "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----";
  document.getElementById("mb-key-pass").value = "";
  setMailboxAuth(m ? m.authMethod || "secret" : "secret");
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

/** Shows the fields for the chosen credential kind and ticks its radio. */
function setMailboxAuth(method) {
  const cert = method === "certificate";
  document.querySelectorAll('input[name="mb-auth"]').forEach((r) => { r.checked = r.value === (cert ? "certificate" : "secret"); });
  document.getElementById("mb-auth-secret").hidden = cert;
  document.getElementById("mb-auth-certificate").hidden = !cert;
}

function mailboxAuthMethod() {
  const picked = document.querySelector('input[name="mb-auth"]:checked');
  return picked ? picked.value : "secret";
}

document.querySelectorAll('input[name="mb-auth"]').forEach((r) => r.addEventListener("change", () => setMailboxAuth(mailboxAuthMethod())));

addMailboxBtn.addEventListener("click", () => openMailboxForm(null));
document.getElementById("mb-cancel").addEventListener("click", closeMailboxForm);

document.getElementById("mb-save").addEventListener("click", async () => {
  const type = document.getElementById("mb-type").value;
  if (type !== "graph") {
    const values = collectSourceFields(type, "mbf");
    const problem = sourceFieldProblem(type, values, { editing: Boolean(editingMailboxId) });
    if (problem) return showSyncMessage(problem, true);
    const other = { type, name: document.getElementById("mb-name").value, enabled: document.getElementById("mb-enabled").checked, ...values };
    try {
      const data = editingMailboxId
        ? await api(`/api/mailboxes/${encodeURIComponent(editingMailboxId)}`, { method: "PUT", body: JSON.stringify(other) })
        : await api("/api/mailboxes", { method: "POST", body: JSON.stringify(other) });
      closeMailboxForm();
      showSyncMessage(`${editingMailboxId ? "Saved" : "Added"} ${data.mailbox.name}. Use Test to check the connection, then Sync.`);
      await loadSyncStatus();
    } catch (error) {
      showSyncMessage(error.message, true);
    }
    return;
  }
  const body = {
    type: "graph",
    name: document.getElementById("mb-name").value,
    tenantId: document.getElementById("mb-tenant").value,
    clientId: document.getElementById("mb-client").value,
    authMethod: mailboxAuthMethod(),
    clientSecret: document.getElementById("mb-secret").value,
    certPem: document.getElementById("mb-cert").value,
    keyPem: document.getElementById("mb-key").value,
    keyPassphrase: document.getElementById("mb-key-pass").value,
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

function describeGeoip(g) {
  if (!g) return "unknown";
  const src = [];
  if (g.cityDb) src.push("city file");
  if (g.asnDb) src.push("ASN file");
  if (g.online) src.push(`online (${g.onlineProvider})`);
  if (!src.length) return "off - no GeoLite2 files and GEOIP_ONLINE=false";
  const st = g.stats || {};
  return `${src.join(" + ")}; ${formatNumber(st.resolved || 0)} addresses resolved${st.unknown ? `, ${formatNumber(st.unknown)} unknown` : ""}${g.problems && g.problems.length ? `; ${g.problems.join("; ")}` : ""}`;
}

geoipRefreshBtn.addEventListener("click", async () => {
  if (!confirm("Look up country and network again for every source IP? With no local files this sends every address to ip-api.com.")) return;
  try {
    await api("/api/geoip/refresh", { method: "POST", body: JSON.stringify({ all: true }) });
    showSyncMessage("GeoIP lookups started in the background; refresh in a minute.");
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
  if (job.tls) bits.push(`${job.tls} TLS report${job.tls === 1 ? "" : "s"}`);
  if (job.forensic) bits.push(`${job.forensic} forensic`);
  if (job.duplicates) bits.push(`${job.duplicates} duplicate${job.duplicates === 1 ? "" : "s"}`);
  if (job.noReport) bits.push(`${job.noReport} without a report`);
  if (job.errors) bits.push(`${job.errors} error${job.errors === 1 ? "" : "s"}`);
  const retries = (job.mailboxes || []).reduce((n, b) => n + (b.retries || 0), 0);
  if (retries) bits.push(`${retries} connection retr${retries === 1 ? "y" : "ies"}`);
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
  if (st.version) renderVersion(st.version);
}
