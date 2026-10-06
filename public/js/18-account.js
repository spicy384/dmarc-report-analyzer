// 18-account.js: Passkeys, sessions, the audit log, the account panel.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- passkeys (WebAuthn) ---------------------------------------------------------
//
// The browser API wants ArrayBuffers where the server speaks base64url; the newer
// PublicKeyCredential JSON helpers do that conversion natively and are used when
// present, with a small fallback for browsers that lack them.

function b64urlToBuffer(s) {
  const b64 = String(s).replace(/-/g, "+").replace(/_/g, "/") + "===".slice((String(s).length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function bufferToB64url(buf) {
  let bin = "";
  for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function webauthnOptionsFromJson(options, kind) {
  if (kind === "create" && PublicKeyCredential.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(options);
  if (kind === "get" && PublicKeyCredential.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(options);
  const out = { ...options, challenge: b64urlToBuffer(options.challenge) };
  if (options.user) out.user = { ...options.user, id: b64urlToBuffer(options.user.id) };
  for (const key of ["excludeCredentials", "allowCredentials"]) {
    if (options[key]) out[key] = options[key].map((c) => ({ ...c, id: b64urlToBuffer(c.id) }));
  }
  return out;
}

function webauthnCredentialToJson(cred) {
  if (typeof cred.toJSON === "function") return cred.toJSON();
  const r = cred.response;
  const response = { clientDataJSON: bufferToB64url(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = bufferToB64url(r.attestationObject);
    if (r.getTransports) response.transports = r.getTransports();
  } else {
    response.authenticatorData = bufferToB64url(r.authenticatorData);
    response.signature = bufferToB64url(r.signature);
    response.userHandle = r.userHandle ? bufferToB64url(r.userHandle) : null;
  }
  return { id: cred.id, rawId: bufferToB64url(cred.rawId), type: cred.type, response, clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}, authenticatorAttachment: cred.authenticatorAttachment || null };
}

/** Why passkeys cannot be used on this page, or null when they can. */
function passkeyBlocker() {
  if (!window.PublicKeyCredential || !navigator.credentials) return "This browser does not support passkeys.";
  if (!window.isSecureContext) return "Passkeys need HTTPS (or localhost).";
  const host = location.hostname;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.startsWith("[")) return "Passkeys need a hostname, not an IP address; open the app by its DNS name.";
  return null;
}

async function signInWithPasskey() {
  const btn = document.getElementById("auth-passkey-btn");
  btn.disabled = true;
  try {
    const { token, options } = await api("/api/auth/passkeys/login/options", { method: "POST", body: "{}" });
    const cred = await navigator.credentials.get({ publicKey: webauthnOptionsFromJson(options, "get") });
    const data = await api("/api/auth/passkeys/login/verify", { method: "POST", body: JSON.stringify({ token, response: webauthnCredentialToJson(cred) }) });
    applyIdentity(data.user, data.csrfToken);
    await onSignedIn();
  } catch (error) {
    // The browser throws NotAllowedError when the prompt is cancelled or times out.
    setAuthMessage(error.name === "NotAllowedError" ? "Passkey prompt cancelled." : error.message);
  } finally {
    btn.disabled = false;
  }
}

document.getElementById("auth-passkey-btn").addEventListener("click", signInWithPasskey);

/** Creates a passkey on this device and registers it for the signed-in user. Throws on cancel or refusal. */
async function registerPasskey(name, { refresh = true } = {}) {
  const { options } = await api("/api/auth/passkeys/register/options", { method: "POST", body: "{}" });
  const cred = await navigator.credentials.create({ publicKey: webauthnOptionsFromJson(options, "create") });
  const data = await api("/api/auth/passkeys/register/verify", { method: "POST", body: JSON.stringify({ name, response: webauthnCredentialToJson(cred) }) });
  renderPasskeys(data.passkeys);
  // Re-reading the identity also closes the sign-in overlay, which the first-sign-in step must keep open.
  if (refresh) await refreshIdentity();
  return data;
}

async function addPasskey() {
  const name = prompt("Name this passkey (for example: work laptop, phone):", "");
  if (name === null) return;
  try {
    const data = await registerPasskey(name);
    setStatus(`Passkey "${data.passkey.name}" added.`);
  } catch (error) {
    setStatus(error.name === "NotAllowedError" ? "Passkey prompt cancelled." : error.name === "InvalidStateError" ? "This device already holds a passkey for your account." : error.message, true);
  }
}

document.getElementById("acct-add-passkey").addEventListener("click", addPasskey);

function renderPasskeys(list) {
  const ul = document.getElementById("acct-passkeys");
  ul.replaceChildren();
  for (const p of list) {
    const li = document.createElement("li");
    const row = document.createElement("div");
    row.className = "passkey-row";
    const text = document.createElement("div");
    const name = document.createElement("div");
    name.className = "passkey-name";
    name.textContent = p.name;
    const meta = document.createElement("div");
    meta.className = "passkey-meta";
    meta.textContent = `Added ${formatTimestamp(Math.floor(p.createdAt / 1000))}${p.lastUsedAt ? `, last used ${formatTimestamp(Math.floor(p.lastUsedAt / 1000))}` : ", never used"}${p.backedUp ? ", synced" : ""}`;
    text.append(name, meta);
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "ghost-danger small";
    remove.textContent = "Remove";
    remove.addEventListener("click", async () => {
      if (!confirm(`Remove the passkey "${p.name}"? You can still sign in with your password.`)) return;
      try {
        const data = await api(`/api/auth/passkeys/${encodeURIComponent(p.id)}`, { method: "DELETE" });
        renderPasskeys(data.passkeys);
        await refreshIdentity();
        setStatus("Passkey removed.");
      } catch (error) {
        setStatus(error.message, true);
      }
    });
    row.append(text, remove);
    li.appendChild(row);
    ul.appendChild(li);
  }
  if (!list.length) {
    const li = document.createElement("li");
    li.className = "passkey-meta";
    li.textContent = "No passkeys yet.";
    ul.appendChild(li);
  }
}

async function loadPasskeys() {
  const blocker = passkeyBlocker();
  const note = document.getElementById("acct-passkey-note");
  note.hidden = !blocker;
  note.textContent = blocker || "";
  document.getElementById("acct-add-passkey").hidden = Boolean(blocker);
  try {
    const data = await api("/api/auth/passkeys");
    renderPasskeys(data.passkeys || []);
  } catch (error) {
    renderPasskeys([]);
  }
}

// --- sessions ------------------------------------------------------------------

/** "Chrome on Windows" from a user-agent string; falls back to the raw start of it. */
function describeAgent(ua) {
  const s = String(ua || "");
  if (!s) return "unknown browser";
  const browser = /Edg\//.test(s) ? "Edge" : /OPR\//.test(s) ? "Opera" : /Firefox\//.test(s) ? "Firefox" : /Chrome\//.test(s) ? "Chrome" : /Safari\//.test(s) ? "Safari" : s.slice(0, 30);
  const os = /Windows/.test(s) ? "Windows" : /Android/.test(s) ? "Android" : /iPhone|iPad/.test(s) ? "iOS" : /Mac OS X/.test(s) ? "macOS" : /Linux/.test(s) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

async function loadSessions() {
  const box = document.getElementById("acct-sessions");
  try {
    const data = await api("/api/auth/sessions");
    const rows = data.sessions || [];
    box.replaceChildren(buildTable(
      ["Where", "Address", "Signed in", "Last active", ""],
      rows.map((s) => {
        const actions = document.createElement("td");
        if (!s.current) {
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "ghost-danger small";
          btn.textContent = "End session";
          btn.addEventListener("click", async () => {
            try {
              await api(`/api/auth/sessions/${encodeURIComponent(s.key)}`, { method: "DELETE" });
              await loadSessions();
            } catch (error) {
              setStatus(error.message, true);
            }
          });
          actions.appendChild(btn);
        }
        return {
          data: s,
          cells: [
            textCell(`${describeAgent(s.userAgent)}${s.current ? " (this one)" : ""}`, s.current ? "" : "muted"),
            textCell(s.ip || "", "mono muted"),
            textCell(formatTimestamp(Math.floor(s.createdAt / 1000)), "nowrap muted"),
            textCell(formatTimestamp(Math.floor(s.lastSeenAt / 1000)), "nowrap"),
            actions
          ]
        };
      }),
      { emptyText: data.viaProxy ? "Signed in through the reverse proxy; there are no app sessions to list." : "No sessions." }
    ));
    document.getElementById("acct-signout-others").hidden = rows.filter((s) => !s.current).length === 0;
  } catch (error) {
    box.replaceChildren();
    setStatus(error.message, true);
  }
}

document.getElementById("acct-signout-others").addEventListener("click", async () => {
  try {
    const data = await api("/api/auth/sessions/sign-out-others", { method: "POST", body: "{}" });
    setStatus(`Signed out ${data.ended} other session${data.ended === 1 ? "" : "s"}.`);
    await loadSessions();
  } catch (error) {
    setStatus(error.message, true);
  }
});

document.getElementById("acct-signout-all").addEventListener("click", async () => {
  if (!confirm("Sign out of every device, including this one?")) return;
  try {
    await api("/api/auth/sessions/sign-out-all", { method: "POST", body: "{}" });
  } catch {
    // The session is gone either way.
  }
  applyIdentity(null, null);
  document.title = BASE_TITLE;
  showAuthOverlay("login");
});

// --- audit log -------------------------------------------------------------------

const auditState = { before: null, rows: [] };

const ACTION_LABELS = {
  "auth.setup": "created the first administrator", "auth.login": "signed in", "auth.logout": "signed out",
  "session.revoke": "ended a session", "session.sign_out_others": "signed out other devices", "session.sign_out_all": "signed out everywhere",
  "mfa.enable": "turned on two-factor", "mfa.disable": "turned off two-factor", "password.change": "changed password",
  "passkey.add": "added a passkey", "passkey.remove": "removed a passkey",
  "user.add": "added user", "user.remove": "removed user", "user.role": "changed role of", "user.reset_mfa": "reset two-factor for",
  "mailbox.add": "added mailbox", "mailbox.update": "changed mailbox", "mailbox.remove": "removed mailbox",
  "sender.add": "labelled sender", "sender.update": "changed label", "sender.remove": "removed label",
  "backup.download": "downloaded a backup", "backup.restore": "restored a backup", "reports.reprocess": "re-processed stored reports",
  "notify.update": "changed notification settings", "notify.test": "sent a test notification"
};

function renderAudit() {
  const rows = auditState.rows;
  document.getElementById("audit-count").textContent = `${rows.length} entr${rows.length === 1 ? "y" : "ies"}`;
  document.getElementById("audit-results").replaceChildren(buildTable(
    ["When", "Who", "What", "Target", "Detail", "From"],
    rows.map((e) => ({
      data: e,
      cells: [
        textCell(formatTimestamp(e.at), "nowrap muted"),
        textCell(e.username || "", "nowrap"),
        textCell(ACTION_LABELS[e.action] || e.action, "nowrap"),
        textCell(e.target || "", "mono trunc"),
        textCell(e.detail || "", "muted trunc-wide"),
        textCell(e.ip || "", "mono muted")
      ]
    })),
    { emptyText: "Nothing recorded yet." }
  ));
}

async function loadAudit({ more = false } = {}) {
  if (!isAdmin()) return;
  if (!more) { auditState.before = null; auditState.rows = []; }
  const filter = document.getElementById("audit-filter").value;
  try {
    const data = await api(`/api/audit?limit=100${auditState.before ? `&before=${auditState.before}` : ""}${filter ? `&action=${encodeURIComponent(filter)}` : ""}`);
    auditState.rows = auditState.rows.concat(data.entries || []);
    auditState.before = auditState.rows.length ? auditState.rows[auditState.rows.length - 1].id : null;
    document.getElementById("audit-more").hidden = !data.more;
    renderAudit();
  } catch (error) {
    setStatus(error.message, true);
  }
}

document.getElementById("audit-filter").addEventListener("change", () => loadAudit());
document.getElementById("audit-more").addEventListener("click", () => loadAudit({ more: true }));

function renderAccountPanel() {
  loadSessions();
  const enrolled = Boolean(currentUser?.mfaEnrolled);
  document.getElementById("account-mfa-state").textContent = `Two-factor: ${enrolled ? "on" : "off"}`;
  document.getElementById("acct-enable-mfa").hidden = enrolled;
  document.getElementById("acct-disable-mfa").hidden = !enrolled;
  if (currentUser) loadPasskeys();
}

document.getElementById("acct-enable-mfa").addEventListener("click", () => beginEnrolment({ offerPasskey: false }));

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
      user.lastLoginAt ? formatTimestamp(Math.floor(user.lastLoginAt / 1000)) : "Never"
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

// --- display time zone ------------------------------------------------------------

(function setupTimeZonePicker() {
  const select = document.getElementById("acct-timezone");
  let zones;
  try {
    zones = typeof Intl.supportedValuesOf === "function" ? Intl.supportedValuesOf("timeZone") : [];
  } catch {
    zones = [];
  }
  const browserZone = (() => {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone;
    } catch {
      return null;
    }
  })();
  if (browserZone) select.options[0].textContent = `This browser's zone (${browserZone})`;
  for (const z of zones) {
    if (z === "UTC") continue;
    const opt = document.createElement("option");
    opt.value = z;
    opt.textContent = z;
    select.appendChild(opt);
  }
  select.value = displayTimeZone;
  if (select.value !== displayTimeZone) {
    // A zone this browser does not know: fall back rather than show a blank picker.
    setDisplayTimeZone("local");
    select.value = "local";
  }
  select.addEventListener("change", () => {
    setDisplayTimeZone(select.value);
    setStatus(`Times are now shown in ${select.value === "local" ? "this browser's zone" : select.value}.`);
    loadAll();
  });
})();

/** Loads everything the signed-in app needs. */
