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
const { createImapSource } = require("./source-imap");
const { createPop3Source } = require("./source-pop3");
const { createGmailSource, parseServiceAccount } = require("./source-gmail");
const { createS3Source } = require("./source-s3");

const AUTH_METHODS = ["secret", "certificate"];

// Where a mailbox's mail comes from. Entries written before types existed are Microsoft 365.
const TYPES = {
  graph: { label: "Microsoft 365", auth: null, secrets: ["clientSecret", "certPem", "keyPem", "keyPassphrase"] },
  gws: { label: "Google Workspace", auth: "service account", secrets: ["serviceAccountKey"] },
  ses: { label: "Amazon SES (S3)", auth: "access key", secrets: ["secretAccessKey"] },
  imap: { label: "IMAP", auth: "password", secrets: ["password"] },
  pop3: { label: "POP3", auth: "password", secrets: ["password"] }
};
const ALL_SECRETS = [...new Set(Object.values(TYPES).flatMap((t) => t.secrets))];
const SECURITY = ["tls", "starttls", "none"];

function typeOf(entry) {
  return TYPES[entry.type] ? entry.type : "graph";
}

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
  const type = typeOf(entry);
  const rest = Object.fromEntries(Object.entries(entry).filter(([k]) => !ALL_SECRETS.includes(k)));
  const base = { ...rest, type, typeLabel: TYPES[type].label };
  if (type === "graph") {
    const method = entry.authMethod || (entry.certPem ? "certificate" : "secret");
    return {
      ...base,
      authMethod: method,
      hasSecret: Boolean(entry.clientSecret),
      hasCertificate: Boolean(entry.certPem),
      certificate: method === "certificate" ? certificateInfo(certificateOf(entry)) : null
    };
  }
  const view = { ...base, authMethod: TYPES[type].auth, hasSecret: TYPES[type].secrets.every((k) => Boolean(entry[k])), hasCertificate: false, certificate: null };
  if (type === "gws") {
    // The service account's address is not a secret and says which key is in use.
    try {
      view.serviceAccount = parseServiceAccount(entry.serviceAccountKey).client_email;
    } catch (error) {
      view.serviceAccount = null;
      view.credentialError = error.message;
    }
  }
  return view;
}

/** What makes two entries "the same mailbox", per type. */
function identity(entry) {
  const type = typeOf(entry);
  if (type === "graph") return `graph|${entry.tenantId}|${entry.mailbox}`;
  if (type === "gws") return `gws|${entry.mailbox}|${entry.folder || ""}`;
  if (type === "ses") return `ses|${entry.bucket}|${entry.prefix || ""}`;
  if (type === "imap") return `imap|${entry.host}|${entry.username}|${entry.folder || "INBOX"}`;
  return `pop3|${entry.host}|${entry.username}`;
}

/**
 * @param sourceOptions per-type options passed to the source factories (tests inject fakes here),
 *   e.g. { imap: { ImapClient }, gws: { fetchImpl }, ses: { fetchImpl } }
 */
function createMailboxStore({ dataDir, env = {}, loginBase, graphBase, sourceOptions = {} } = {}) {
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
    const type = clean(fields.type) || "graph";
    if (!TYPES[type]) throw fail(400, `Type must be one of: ${Object.keys(TYPES).join(", ")}.`);
    const enabled = fields.enabled === undefined ? true : Boolean(fields.enabled);
    const checkName = (name) => {
      if (name.length > 80) throw fail(400, "Name is too long (80 characters maximum).");
      return name;
    };

    if (type === "imap" || type === "pop3") {
      const host = clean(fields.host).toLowerCase();
      const security = clean(fields.security) || "tls";
      const username = clean(fields.username);
      const password = fields.password === undefined || fields.password === null ? "" : String(fields.password);
      const portText = clean(fields.port);
      const port = portText ? Number(portText) : (type === "imap" ? (security === "tls" ? 993 : 143) : (security === "tls" ? 995 : 110));
      if (!host || /\s/.test(host)) throw fail(400, "Server host name is required.");
      if (!SECURITY.includes(security)) throw fail(400, "Security must be tls, starttls or none.");
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw fail(400, "Port must be a number between 1 and 65535.");
      if (!username) throw fail(400, "Username is required.");
      if (!password) throw fail(400, "Password is required.");
      const mailbox = (clean(fields.mailbox) || username).toLowerCase();
      const entry = { type, name: checkName(clean(fields.name) || mailbox), host, port, security, username, password, tlsVerify: fields.tlsVerify === undefined ? true : Boolean(fields.tlsVerify), mailbox, enabled };
      // POP3 has no folders.
      entry.folder = type === "imap" ? (clean(fields.folder) || "INBOX") : "";
      return entry;
    }

    if (type === "gws") {
      const mailbox = clean(fields.mailbox).toLowerCase();
      const serviceAccountKey = typeof fields.serviceAccountKey === "object" && fields.serviceAccountKey ? JSON.stringify(fields.serviceAccountKey) : clean(fields.serviceAccountKey);
      if (!mailbox || !/^[^\s@]+@[^\s@]+$/.test(mailbox)) throw fail(400, "Mailbox must be the email address of the Google Workspace user to read.");
      if (!serviceAccountKey) throw fail(400, "Service account key (JSON) is required.");
      try {
        parseServiceAccount(serviceAccountKey);
      } catch (error) {
        throw fail(400, error.message);
      }
      // "folder" is a Gmail label here; empty means the whole mailbox.
      return { type, name: checkName(clean(fields.name) || mailbox), mailbox, serviceAccountKey, folder: clean(fields.folder), enabled };
    }

    if (type === "ses") {
      const region = clean(fields.region).toLowerCase();
      const bucket = clean(fields.bucket);
      const prefix = clean(fields.prefix).replace(/^\/+/, "");
      const accessKeyId = clean(fields.accessKeyId);
      const secretAccessKey = clean(fields.secretAccessKey);
      const endpoint = clean(fields.endpoint);
      if (!/^[a-z0-9-]+$/.test(region)) throw fail(400, "Region is required, for example us-east-1.");
      if (!bucket || /\s|\//.test(bucket)) throw fail(400, "Bucket name is required (just the name, no s3:// or slashes).");
      if (!accessKeyId) throw fail(400, "Access key ID is required.");
      if (!secretAccessKey) throw fail(400, "Secret access key is required.");
      if (endpoint && !/^https?:\/\//.test(endpoint)) throw fail(400, "Endpoint must be a URL starting with http:// or https://.");
      const mailbox = (clean(fields.mailbox) || `s3://${bucket}/${prefix}`).toLowerCase();
      return { type, name: checkName(clean(fields.name) || mailbox), mailbox, region, bucket, prefix, accessKeyId, secretAccessKey, endpoint, folder: "", enabled };
    }

    return { type: "graph", ...validateGraph(fields) };
  }

  function validateGraph(fields) {
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
    if (all().some((m) => identity(m) === identity(entry))) {
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
    const type = typeOf(current);
    if (fields.type !== undefined && clean(fields.type) && clean(fields.type) !== type) {
      throw fail(400, "A mailbox's type cannot be changed; add a new mailbox of the other type instead.");
    }
    // Blank credential fields mean "keep the stored one" (the UI never sends them back).
    const kept = type === "graph"
      ? {
        clientSecret: clean(fields.clientSecret) || current.clientSecret || "",
        certPem: clean(fields.certPem) || current.certPem || "",
        keyPem: clean(fields.certPem) ? clean(fields.keyPem) : clean(fields.keyPem) || current.keyPem || "",
        keyPassphrase: fields.keyPassphrase === undefined || fields.keyPassphrase === "" ? current.keyPassphrase || "" : fields.keyPassphrase
      }
      : Object.fromEntries(TYPES[type].secrets.map((k) => [k, (typeof fields[k] === "object" && fields[k] ? fields[k] : clean(fields[k])) || current[k] || ""]));
    const merged = validate({ ...current, ...fields, type, ...kept });
    if (all().some((m) => m.id !== id && identity(m) === identity(merged))) {
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
    const type = typeOf(entry);
    // Message ids carry the mailbox id so the same UID in two mailboxes never collides.
    const idPrefix = `${type}:${entry.id}:`;
    if (type === "imap") {
      return createImapSource({ host: entry.host, port: entry.port, security: entry.security, username: entry.username, password: entry.password, folder: entry.folder, tlsVerify: entry.tlsVerify }, { idPrefix, ...(sourceOptions.imap || {}) });
    }
    if (type === "pop3") {
      return createPop3Source({ host: entry.host, port: entry.port, security: entry.security, username: entry.username, password: entry.password, tlsVerify: entry.tlsVerify }, { idPrefix, ...(sourceOptions.pop3 || {}) });
    }
    if (type === "gws") {
      return createGmailSource({ serviceAccountKey: entry.serviceAccountKey, mailbox: entry.mailbox, folder: entry.folder, ...(sourceOptions.gwsConfig || {}) }, { idPrefix, ...(sourceOptions.gws || {}) });
    }
    if (type === "ses") {
      return createS3Source({ region: entry.region, bucket: entry.bucket, prefix: entry.prefix, accessKeyId: entry.accessKeyId, secretAccessKey: entry.secretAccessKey, endpoint: entry.endpoint || undefined }, { idPrefix, ...(sourceOptions.ses || {}) });
    }
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

  /** Enabled mailboxes with a client each (Graph or another source), in configuration order. */
  function enabledWithClients() {
    return all().filter((m) => m.enabled).map((m) => ({ id: m.id, name: m.name, mailbox: m.mailbox, client: clientFor(m.id) }));
  }

  async function testConnection(id) {
    return clientFor(id).testConnection();
  }

  return { ENV_ID, list, get, add, update, remove, clientFor, enabledWithClients, testConnection, file: FILE };
}

module.exports = { createMailboxStore, ENV_ID, TYPES };
