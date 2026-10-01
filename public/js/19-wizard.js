// 19-wizard.js: First-run walkthrough and onSignedIn().
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- first-run walkthrough -------------------------------------------------------
//
// Shown to an administrator right after sign-in while no mailbox is configured (no
// GRAPH_* variables and nothing added in the app), until it is skipped. Reopenable
// from the Mailbox sync panel. It drives the same /api/mailboxes endpoints as the form.

const setupWizard = document.getElementById("setup-wizard");
const swMessage = document.getElementById("sw-message");
const swBack = document.getElementById("sw-back");
const swNext = document.getElementById("sw-next");
const swSync = document.getElementById("sw-sync");
const swFinish = document.getElementById("sw-finish");
const swSkip = document.getElementById("sw-skip");
const setupGuideBtn = document.getElementById("setup-guide-btn");
const swState = { step: 1, mailboxId: null, busy: false, testOk: false };

function swSay(text, isError = false) {
  swMessage.textContent = text || "";
  swMessage.hidden = !text;
  swMessage.classList.toggle("is-error", Boolean(isError));
}

function swAuthMethod() {
  const picked = document.querySelector('input[name="sw-auth"]:checked');
  return picked ? picked.value : "secret";
}

document.querySelectorAll('input[name="sw-auth"]').forEach((r) => r.addEventListener("change", () => {
  const cert = swAuthMethod() === "certificate";
  document.getElementById("sw-auth-secret").hidden = cert;
  document.getElementById("sw-auth-certificate").hidden = !cert;
}));

function swShow(step) {
  swState.step = step;
  swSay("");
  for (let i = 1; i <= 4; i += 1) document.getElementById(`sw-step-${i}`).hidden = i !== step;
  document.getElementById("sw-progress").textContent = `Step ${step} of 4`;
  swBack.hidden = step === 1 || step === 4 && swState.testOk;
  swNext.hidden = step === 4;
  swNext.textContent = step === 1 ? "Get started" : step === 3 ? "Save and test the connection" : "Next";
  swSync.hidden = !(step === 4 && swState.testOk);
  swFinish.hidden = step !== 4;
  swFinish.textContent = swState.testOk ? "Finish without syncing" : "Finish anyway";
  swSkip.hidden = step === 4;
  const graph = swType() === "graph";
  const focus = { 2: "sw-type", 3: graph ? "sw-mailbox" : "sw-name" }[step];
  if (focus) document.getElementById(focus).focus();
}

function swType() {
  return document.getElementById("sw-type").value || "graph";
}

/** Shows the Microsoft 365 fields or the generated ones for another type, in steps 2 and 3. */
function setWizardType(type) {
  const graph = type === "graph";
  setupWizard.querySelectorAll(".sw-graph-only").forEach((el) => { el.hidden = !graph; });
  const other = document.getElementById("sw-other");
  const intro = document.getElementById("sw-type-intro");
  other.hidden = graph;
  intro.hidden = graph || !SOURCE_TYPES[type].intro;
  intro.textContent = graph ? "" : SOURCE_TYPES[type].intro || "";
  renderSourceFields(other, type, "swf");
  // A saved attempt belongs to the type it was made with.
  swState.mailboxId = null;
}

document.getElementById("sw-type").addEventListener("change", (event) => setWizardType(event.target.value));

function openSetupWizard() {
  swState.mailboxId = null;
  swState.testOk = false;
  setupWizard.hidden = false;
  setWizardType(swType());
  swShow(1);
}

function closeSetupWizard() {
  setupWizard.hidden = true;
}

/** The mailbox fields as the API wants them; throws a message for the first thing missing. */
function swCollect() {
  if (swType() !== "graph") {
    return { type: swType(), name: document.getElementById("sw-name").value.trim(), enabled: true, ...collectSourceFields(swType(), "swf") };
  }
  const tenantId = document.getElementById("sw-tenant").value.trim();
  const clientId = document.getElementById("sw-client").value.trim();
  const authMethod = swAuthMethod();
  const clientSecret = document.getElementById("sw-secret").value;
  const certPem = document.getElementById("sw-cert").value.trim();
  const keyPem = document.getElementById("sw-key").value.trim();
  const keyPassphrase = document.getElementById("sw-key-pass").value;
  const mailbox = document.getElementById("sw-mailbox").value.trim();
  const folder = document.getElementById("sw-folder").value.trim() || "Inbox";
  const name = document.getElementById("sw-name").value.trim();
  return { type: "graph", tenantId, clientId, authMethod, clientSecret, certPem, keyPem, keyPassphrase, mailbox, folder, name, enabled: true };
}

function swValidateStep2(f) {
  // After a failed test the mailbox is saved, so an empty secret means "keep it".
  if (f.type !== "graph") return sourceFieldProblem(f.type, f, { editing: Boolean(swState.mailboxId) });
  if (!f.tenantId) return "Enter the Directory (tenant) ID.";
  if (!f.clientId) return "Enter the Application (client) ID.";
  if (f.authMethod === "secret" && !f.clientSecret) return "Enter the client secret's value.";
  if (f.authMethod === "certificate" && !f.certPem) return "Paste the certificate (PEM).";
  if (f.authMethod === "certificate" && !f.keyPem && !/PRIVATE KEY/.test(f.certPem)) return "Paste the private key (PEM), or a combined PEM holding both.";
  return null;
}

function swValidateStep3(f) {
  if (f.type !== "graph") return null;
  if (!f.mailbox || !/^[^\s@]+@[^\s@]+$/.test(f.mailbox)) return "Enter the mailbox address, for example dmarc-reports@contoso.com.";
  return null;
}

/** Saves the mailbox (create, or update after a failed attempt) and runs the connection test. */
async function swSaveAndTest() {
  const f = swCollect();
  // Blank credential fields on an update mean "keep what was saved".
  const saved = swState.mailboxId
    ? await api(`/api/mailboxes/${encodeURIComponent(swState.mailboxId)}`, { method: "PUT", body: JSON.stringify(f) })
    : await api("/api/mailboxes", { method: "POST", body: JSON.stringify(f) });
  swState.mailboxId = saved.mailbox.id;
  const result = await api(`/api/mailboxes/${encodeURIComponent(swState.mailboxId)}/test`, { method: "POST", body: "{}" });
  swState.testOk = Boolean(result.ok);
  const box = document.getElementById("sw-result");
  box.replaceChildren();
  const status = document.createElement("p");
  status.className = `wizard-status ${result.ok ? "is-ok" : "is-bad"}`;
  status.textContent = result.ok ? "Connected." : `Connection test failed at the ${result.stage || "connection"} stage.`;
  const detail = document.createElement("p");
  detail.className = "wizard-detail";
  detail.textContent = result.detail || "";
  box.append(status, detail);
  document.getElementById("sw-result-hint").textContent = result.ok
    ? `The mailbox is saved and enabled. The first sync looks back ${syncStatusBackfillDays || 90} days; later runs continue from the newest email seen.`
    : "The mailbox is saved, so nothing is lost: go back to correct the details and test again, or finish now and fix it later under Mailbox sync. "
      + (f.type !== "graph"
        // The other sources explain themselves in the detail line; this says what kind of thing to fix.
        ? ({
          connection: "The server could not be reached: check the host name, port and security setting.",
          login: "The sign-in was refused: check the credential, and for Google that domain-wide delegation is granted.",
          folder: "The sign-in worked; check the folder name.",
          list: "The sign-in worked, but listing the mailbox failed; the detail above says why.",
          config: "A required setting is missing."
        })[result.stage] || ""
        : result.stage === "token"
          ? "A token failure usually means a wrong tenant ID, client ID or credential."
          : result.stage === "folder" || result.stage === "mailbox"
            ? "Reaching the token stage means the credential works; check the mailbox address, the Mail.Read permission and its admin consent, and any application access policy."
            : "");
  swShow(4);
}

let syncStatusBackfillDays = 0;

swNext.addEventListener("click", async () => {
  if (swState.busy) return;
  const f = swCollect();
  if (swState.step === 1) return swShow(2);
  if (swState.step === 2) {
    const problem = swValidateStep2(f);
    if (problem) return swSay(problem, true);
    return swShow(3);
  }
  if (swState.step === 3) {
    const problem = swValidateStep3(f);
    if (problem) return swSay(problem, true);
    swState.busy = true;
    swNext.disabled = true;
    swNext.textContent = "Testing...";
    try {
      await swSaveAndTest();
    } catch (error) {
      swSay(error.message, true);
    } finally {
      swState.busy = false;
      swNext.disabled = false;
      if (swState.step === 3) swNext.textContent = "Save and test the connection";
    }
  }
});

swBack.addEventListener("click", () => swShow(Math.max(1, swState.step - 1)));

swSkip.addEventListener("click", async () => {
  try {
    await api("/api/setup/dismiss", { method: "POST", body: "{}" });
  } catch {
    // Dismissal is a convenience; the wizard just closes for this session.
  }
  closeSetupWizard();
});

swFinish.addEventListener("click", async () => {
  closeSetupWizard();
  await loadSyncStatus();
  setView("settings", { scrollTo: "sync-panel" });
});

swSync.addEventListener("click", async () => {
  closeSetupWizard();
  await startSync({ mailboxId: swState.mailboxId });
  setView("settings", { scrollTo: "sync-panel" });
});

setupGuideBtn.addEventListener("click", () => openSetupWizard());

async function onSignedIn() {
  hideAuthOverlay();
  renderAccountPanel();
  setupGuideBtn.hidden = !isAdmin();
  let status = null;
  try {
    await loadDomains();
    status = await api("/api/status");
    populateMailboxSelect(status.mailboxes || [], status.mailboxCounts || []);
    readHash();
  } catch (_) {
    // The dropdowns are a convenience; the rest still loads.
  }
  await loadAll();
  if (status && status.setup && status.setup.needed && !status.setup.dismissed && isAdmin()) {
    syncStatusBackfillDays = status.backfillDays || 0;
    openSetupWizard();
  }
}
