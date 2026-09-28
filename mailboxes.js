/**
 * The mailboxes the analyzer reads: each is an Entra app registration (tenant,
 * client id, and either a client secret or a certificate with its private key)
 * plus a mailbox address and folder. Stored in <DATA_DIR>/mailboxes.json with
 * mode 600 because it holds those credentials.
 *
 * The mailbox configured through environment variables (GRAPH_* / DMARC_*) is
 * merged in at boot as the read-only entry "env", so single-mailbox installs keep
 * working without touching the file.
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { createGraphClient, loadCertificate, certificateInfo } = require("./graph");

const AUTH_METHODS = ["secret", "certificate"];

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

/** The certificate as a config object for the Graph client, or null. */
function certificateOf(entry) {
  return entry.certPem ? { cert: entry.certPem, key: entry.keyPem || "", passphrase: entry.keyPassphrase || "" } : null;
}

/** Strips every credential; this is what the API and UI see. */
function publicView(entry) {
  const { clientSecret, certPem, keyPem, keyPassphrase, ...rest } = entry;
  const method = entry.authMethod || (certPem ? "certificate" : "secret");
  return {
    ...rest,
    authMethod: method,
    hasSecret: Boolean(clientSecret),
    hasCertificate: Boolean(certPem),
    certificate: method === "certificate" ? certificateInfo(certificateOf(entry)) : null
  };
}

function createMailboxStore({ dataDir, env = {}, loginBase, graphBase } = {}) {
  const FILE = path.join(dataDir, "mailboxes.json");

  const envCert = env.certificate && env.certificate.cert ? env.certificate : null;
  const envEntry = env.tenantId && env.clientId && (env.clientSecret || envCert) && env.mailbox
    ? {
      id: ENV_ID,
      name: `${env.mailbox} (environment)`,
      tenantId: env.tenantId,
      clientId: env.clientId,
      authMethod: envCert ? "certificate" : "secret",
      clientSecret: envCert ? "" : env.clientSecret,
      certPem: envCert ? envCert.cert : "",
      keyPem: envCert ? envCert.key || "" : "",
      keyPassphrase: envCert ? envCert.passphrase || "" : "",
      certificateError: env.certificateError || null,
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

  /**
   * Checks the fields of an add or update. The credential for the chosen method
   * must be present: the caller merges the stored one in first when the request
   * left it blank, so "keep what is there" works for both kinds.
   */
  function validate(fields) {
    const tenantId = clean(fields.tenantId);
    const clientId = clean(fields.clientId);
    const clientSecret = clean(fields.clientSecret);
    const certPem = clean(fields.certPem);
    const keyPem = clean(fields.keyPem);
    const keyPassphrase = fields.keyPassphrase === undefined || fields.keyPassphrase === null ? "" : String(fields.keyPassphrase);
    const authMethod = clean(fields.authMethod) || (certPem && !clientSecret ? "certificate" : "secret");
    const mailbox = clean(fields.mailbox).toLowerCase();
    const folder = clean(fields.folder) || "Inbox";
    const name = clean(fields.name) || mailbox;

    if (!tenantId) throw fail(400, "Tenant ID is required.");
    if (!clientId) throw fail(400, "Client ID is required.");
    if (!AUTH_METHODS.includes(authMethod)) throw fail(400, "Authentication must be \"secret\" or \"certificate\".");
    if (authMethod === "secret" && !clientSecret) throw fail(400, "Client secret is required.");
    if (authMethod === "certificate") {
      if (!certPem) throw fail(400, "Certificate (PEM) is required.");
      try {
        // Also confirms the key matches the certificate and the passphrase opens it.
        loadCertificate({ cert: certPem, key: keyPem, passphrase: keyPassphrase });
      } catch (error) {
        throw fail(400, error.message);
      }
    }
    if (!mailbox || !/^[^\s@]+@[^\s@]+$/.test(mailbox)) throw fail(400, "Mailbox must be an email address (UPN).");
    if (name.length > 80) throw fail(400, "Name is too long (80 characters maximum).");

    return {
      name,
      tenantId,
      clientId,
      authMethod,
      // Only the credential of the chosen method is kept, so switching methods drops the other.
      clientSecret: authMethod === "secret" ? clientSecret : "",
      certPem: authMethod === "certificate" ? certPem : "",
      keyPem: authMethod === "certificate" ? keyPem : "",
      keyPassphrase: authMethod === "certificate" ? keyPassphrase : "",
      mailbox,
      folder,
      enabled: fields.enabled === undefined ? true : Boolean(fields.enabled)
    };
  }

  function add(fields) {
    const entry = validate(fields);
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
    // Blank credential fields mean "keep the stored one" (the UI never sends them back).
    const merged = validate({
      ...current,
      ...fields,
      clientSecret: clean(fields.clientSecret) || current.clientSecret || "",
      certPem: clean(fields.certPem) || current.certPem || "",
      keyPem: clean(fields.certPem) ? clean(fields.keyPem) : clean(fields.keyPem) || current.keyPem || "",
      keyPassphrase: fields.keyPassphrase === undefined || fields.keyPassphrase === "" ? current.keyPassphrase || "" : fields.keyPassphrase
    });
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
    const method = entry.authMethod || (entry.certPem ? "certificate" : "secret");
    return createGraphClient({
      tenantId: entry.tenantId,
      clientId: entry.clientId,
      clientSecret: method === "secret" ? entry.clientSecret : "",
      certificate: method === "certificate" ? certificateOf(entry) : null,
      certificateError: entry.certificateError || null,
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
