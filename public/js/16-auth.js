// 16-auth.js: Sign-in overlay, identity, users.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

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
  // The passkey button only helps where the browser can actually use one.
  document.getElementById("auth-passkey-block").hidden = step !== "login" || Boolean(passkeyBlocker());

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
  viewNav.hidden = !signedIn;
  addMailboxBtn.hidden = !signedIn || user.role !== "admin";
  geoipRefreshBtn.hidden = !signedIn || user.role !== "admin";
  if (!signedIn) mailboxForm.hidden = true;

  if (signedIn) {
    currentUserEl.textContent = user.role === "user" ? user.username : `${user.username} (${user.role})`;
  }

  if (!signedIn) {
    usersPanel.hidden = true;
    accountPanel.hidden = true;
    document.getElementById("maintenance-panel").hidden = true;
    document.getElementById("audit-panel").hidden = true;
    document.getElementById("notify-panel").hidden = true;
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

document.getElementById("recovery-copy").addEventListener("click", async () => {
  const ok = await copyToClipboard(issuedRecoveryCodes.join("\n"));
  setAuthMessage(ok ? "Copied to clipboard." : "Could not copy; select the codes and copy them yourself.", !ok);
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
  alertsBanner.hidden = true;
  document.title = BASE_TITLE;
  showAuthOverlay("login");
});
