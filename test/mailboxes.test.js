/** Mailbox store: env entry, CRUD, validation, secret handling, Graph clients. */
const fs = require("fs");
const os = require("os");
const path = require("path");

const { createChecker } = require("./helpers/assert");
const { createMailboxStore, ENV_ID } = require("../mailboxes");

const { check, report } = createChecker("Mailboxes: store, env entry, validation");
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-mailboxes-"));

const env = { tenantId: "t-env", clientId: "c-env", clientSecret: "s-env", mailbox: "dmarc@env.test", folder: "Inbox" };
const store = createMailboxStore({ dataDir, env, loginBase: "http://127.0.0.1:1", graphBase: "http://127.0.0.1:1/v1.0" });

// --- env entry ------------------------------------------------------------------
let list = store.list();
check("env mailbox is listed first and read-only", list.length === 1 && list[0].id === ENV_ID && list[0].readOnly === true);
check("listing never carries the secret", !("clientSecret" in list[0]) && list[0].hasSecret === true);
check("get() has the secret for internal use", store.get(ENV_ID).clientSecret === "s-env");
check("file not written for the env entry", !fs.existsSync(store.file));

let threw = null;
try { store.update(ENV_ID, { name: "x" }); } catch (e) { threw = e; }
check("env entry cannot be edited", threw && threw.status === 403);
threw = null;
try { store.remove(ENV_ID); } catch (e) { threw = e; }
check("env entry cannot be deleted", threw && threw.status === 403);

// --- validation -----------------------------------------------------------------
const bad = (fields) => { try { store.add(fields); return null; } catch (e) { return e; } };
check("tenant required", bad({ clientId: "c", clientSecret: "s", mailbox: "a@b.test" })?.status === 400);
check("client id required", bad({ tenantId: "t", clientSecret: "s", mailbox: "a@b.test" })?.status === 400);
check("secret required on add", bad({ tenantId: "t", clientId: "c", mailbox: "a@b.test" })?.status === 400);
check("mailbox must look like an address", bad({ tenantId: "t", clientId: "c", clientSecret: "s", mailbox: "not-an-address" })?.status === 400);
check("duplicate of the env mailbox refused", bad({ tenantId: "t-env", clientId: "c", clientSecret: "s", mailbox: "DMARC@env.test" })?.status === 409);

// --- add / update / remove --------------------------------------------------------
const added = store.add({ name: " Contoso ", tenantId: "t-1", clientId: "c-1", clientSecret: "s-1", mailbox: "Reports@Contoso.test", folder: "" });
check("add returns public view", added.id && added.id !== ENV_ID && added.name === "Contoso" && added.mailbox === "reports@contoso.test" && added.folder === "Inbox" && added.enabled === true && !("clientSecret" in added) && added.hasSecret);
check("file written", fs.existsSync(store.file));
check("file holds the secret", JSON.parse(fs.readFileSync(store.file, "utf8"))[0].clientSecret === "s-1");
if (process.platform !== "win32") {
  check("file mode is 600", (fs.statSync(store.file).mode & 0o777) === 0o600);
}
check("listed after env", store.list().length === 2 && store.list()[1].id === added.id);

const second = store.add({ tenantId: "t-2", clientId: "c-2", clientSecret: "s-2", mailbox: "dmarc@fabrikam.test", enabled: false });
check("name defaults to the mailbox, enabled can be false", second.name === "dmarc@fabrikam.test" && second.enabled === false);

const updated = store.update(added.id, { name: "Contoso Ltd", folder: "DMARC/Reports", clientSecret: "" });
check("update keeps the secret when omitted", updated.name === "Contoso Ltd" && updated.folder === "DMARC/Reports" && store.get(added.id).clientSecret === "s-1");
store.update(added.id, { clientSecret: "s-1b" });
check("update replaces the secret when given", store.get(added.id).clientSecret === "s-1b");
threw = null;
try { store.update(added.id, { mailbox: "dmarc@fabrikam.test", tenantId: "t-2" }); } catch (e) { threw = e; }
check("update refuses a duplicate", threw && threw.status === 409);
threw = null;
try { store.update("nope", { name: "x" }); } catch (e) { threw = e; }
check("update of unknown id is 404", threw && threw.status === 404);

// --- clients --------------------------------------------------------------------
const client = store.clientFor(added.id);
check("clientFor builds a configured Graph client", client.isConfigured() && client.config.mailbox === "reports@contoso.test" && client.config.folder === "DMARC/Reports" && client.config.loginBase === "http://127.0.0.1:1");
const enabled = store.enabledWithClients();
check("enabledWithClients skips disabled entries", enabled.length === 2 && enabled.map((e) => e.id).join(",") === `${ENV_ID},${added.id}` && typeof enabled[1].client.listMessages === "function");

store.remove(second.id);
check("remove", store.list().length === 2 && store.get(second.id) === null);
threw = null;
try { store.remove("nope"); } catch (e) { threw = e; }
check("remove of unknown id is 404", threw && threw.status === 404);

// --- without env --------------------------------------------------------------
const bare = createMailboxStore({ dataDir, env: {} });
check("no env entry when variables are missing; file entries still load", bare.list().length === 1 && bare.list()[0].id === added.id);
check("corrupt file is treated as empty", (() => { const d2 = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-mb2-")); fs.writeFileSync(path.join(d2, "mailboxes.json"), "{not json"); const s2 = createMailboxStore({ dataDir: d2 }); const ok = s2.list().length === 0; fs.rmSync(d2, { recursive: true, force: true }); return ok; })());

fs.rmSync(dataDir, { recursive: true, force: true });
process.exit(report() ? 0 : 1);
