/**
 * The mailboxes the analyzer reads: each is an Entra app registration (tenant,
 * client id, client secret) plus a mailbox address and folder. Stored in
 * <DATA_DIR>/mailboxes.json with mode 600 because it holds client secrets.
 *
 * The mailbox configured through environment variables (GRAPH_* / DMARC_*) is
 * merged in at boot as the read-only entry "env", so single-mailbox installs keep
 * working without touching the file.
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { createGraphClient } = require("./graph");

const ENV_ID = "env";

function fail(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function readJson(file, fallback) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    return parsed ?? fallback;
  } catch {
    return fallback;
  }
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2), "utf8");
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    // chmod is a no-op on some Windows setups; not fatal.
  }
}

function clean(value) {
  return value === undefined || value === null ? "" : String(value).trim();
}

/** Strips the secret; this is what the API and UI see. */
function publicView(entry) {
  const { clientSecret, ...rest } = entry;
  return { ...rest, hasSecret: Boolean(clientSecret) };
}

function createMailboxStore({ dataDir, env = {}, loginBase, graphBase } = {}) {
  const FILE = path.join(dataDir, "mailboxes.json");

  const envEntry = env.tenantId && env.clientId && env.clientSecret && env.mailbox
    ? {
      id: ENV_ID,
      name: `${env.mailbox} (environment)`,
      tenantId: env.tenantId,
      clientId: env.clientId,
      clientSecret: env.clientSecret,
      mailbox: env.mailbox,
      folder: env.folder || "Inbox",
      enabled: true,
      readOnly: true,
      createdAt: null,
      updatedAt: null
    }
    : null;

  function load() {
    const raw = readJson(FILE, []);
    return Array.isArray(raw) ? raw.filter((m) => m && typeof m === "object" && m.id && m.id !== ENV_ID) : [];
  }

  function save(list) {
    writeJson(FILE, list);
  }

  /** Every entry, secrets included. For internal use only. */
  function all() {
    return envEntry ? [envEntry, ...load()] : load();
  }

  function list() {
    return all().map(publicView);
  }

  function get(id) {
    return all().find((m) => m.id === id) || null;
  }

  function validate(fields, { requireSecret }) {
    const tenantId = clean(fields.tenantId);
    const clientId = clean(fields.clientId);
    const clientSecret = clean(fields.clientSecret);
    const mailbox = clean(fields.mailbox).toLowerCase();
    const folder = clean(fields.folder) || "Inbox";
    const name = clean(fields.name) || mailbox;

    if (!tenantId) throw fail(400, "Tenant ID is required.");
    if (!clientId) throw fail(400, "Client ID is required.");
    if (requireSecret && !clientSecret) throw fail(400, "Client secret is required.");
    if (!mailbox || !/^[^\s@]+@[^\s@]+$/.test(mailbox)) throw fail(400, "Mailbox must be an email address (UPN).");
    if (name.length > 80) throw fail(400, "Name is too long (80 characters maximum).");

    return { name, tenantId, clientId, clientSecret, mailbox, folder, enabled: fields.enabled === undefined ? true : Boolean(fields.enabled) };
  }

  function add(fields) {
    const entry = validate(fields, { requireSecret: true });
    const list2 = load();
    if (all().some((m) => m.mailbox === entry.mailbox && m.tenantId === entry.tenantId)) {
      throw fail(409, `${entry.mailbox} is already configured.`);
    }
    let id;
    do {
      id = crypto.randomBytes(4).toString("hex");
    } while (all().some((m) => m.id === id));

    const now = Math.floor(Date.now() / 1000);
    const stored = { id, ...entry, readOnly: false, createdAt: now, updatedAt: now };
    list2.push(stored);
    save(list2);
    return publicView(stored);
  }

  function update(id, fields) {
    if (id === ENV_ID) throw fail(403, "The environment-configured mailbox can only be changed through its environment variables.");
    const list2 = load();
    const index = list2.findIndex((m) => m.id === id);
    if (index < 0) throw fail(404, "No such mailbox.");

    const current = list2[index];
    const merged = validate({ ...current, ...fields, clientSecret: clean(fields.clientSecret) || current.clientSecret }, { requireSecret: true });
    if (all().some((m) => m.id !== id && m.mailbox === merged.mailbox && m.tenantId === merged.tenantId)) {
      throw fail(409, `${merged.mailbox} is already configured.`);
    }
    const stored = { ...current, ...merged, updatedAt: Math.floor(Date.now() / 1000) };
    list2[index] = stored;
    save(list2);
    return publicView(stored);
  }

  function remove(id) {
    if (id === ENV_ID) throw fail(403, "The environment-configured mailbox cannot be deleted here; unset its environment variables instead.");
    const list2 = load();
    const next = list2.filter((m) => m.id !== id);
    if (next.length === list2.length) throw fail(404, "No such mailbox.");
    save(next);
    return true;
  }

  function clientFor(id) {
    const entry = get(id);
    if (!entry) throw fail(404, "No such mailbox.");
    return createGraphClient({
      tenantId: entry.tenantId,
      clientId: entry.clientId,
      clientSecret: entry.clientSecret,
      mailbox: entry.mailbox,
      folder: entry.folder,
      ...(loginBase ? { loginBase } : {}),
      ...(graphBase ? { graphBase } : {})
    });
  }

  /** Enabled mailboxes with a Graph client each, in configuration order. */
  function enabledWithClients() {
    return all().filter((m) => m.enabled).map((m) => ({ id: m.id, name: m.name, mailbox: m.mailbox, client: clientFor(m.id) }));
  }

  async function testConnection(id) {
    return clientFor(id).testConnection();
  }

  return { ENV_ID, list, get, add, update, remove, clientFor, enabledWithClients, testConnection, file: FILE };
}

module.exports = { createMailboxStore, ENV_ID };
