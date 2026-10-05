/**
 * Minimal Microsoft Graph client for reading one mailbox with application
 * permissions (client credentials). Uses Node's built-in fetch; no MSAL.
 *
 * Only what the sync needs: a token, a folder lookup, message listing with
 * paging, and attachment download. Throttling (429/503) is retried honouring
 * Retry-After; permission problems are turned into messages that say what to fix.
 */

const { describeFetchError } = require("./net-errors");
const crypto = require("crypto");
const fs = require("fs");

class GraphError extends Error {
  constructor(message, { status, code, retryable = false } = {}) {
    super(message);
    this.name = "GraphError";
    this.status = status;
    this.code = code;
    this.retryable = retryable;
  }
}

const DEFAULT_LOGIN_BASE = "https://login.microsoftonline.com";
const DEFAULT_GRAPH_BASE = "https://graph.microsoft.com/v1.0";
const MAX_RETRIES = 5;
const PAGE_SIZE = 100;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function odataString(value) {
  // Single quotes are escaped by doubling inside OData string literals.
  return `'${String(value).replace(/'/g, "''")}'`;
}

// --- certificate credentials --------------------------------------------------
//
// Entra accepts a signed JWT (a "client assertion", RFC 7523) in place of a client
// secret. The app signs it with the certificate's private key; Entra checks the
// signature against the public certificate uploaded to the app registration,
// matched by the SHA-1 thumbprint in the token header (x5t). Nothing but Node's
// crypto module is needed.

function base64url(input) {
  return Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Parses a certificate and private key (PEM) and checks they belong together.
 * `cert` may be a combined PEM holding both; `key` is then optional.
 * Returns { cert (X509Certificate), key (KeyObject), thumbprint, subject, notAfter }.
 */
function loadCertificate({ cert, key, passphrase } = {}) {
  const certPem = String(cert || "").trim();
  const keyPem = String(key || "").trim() || certPem;
  if (!certPem) {
    throw new GraphError("No certificate given.", { code: "certificate" });
  }
  let x509;
  try {
    x509 = new crypto.X509Certificate(certPem);
  } catch (error) {
    throw new GraphError(`The certificate could not be read (expected PEM with a BEGIN CERTIFICATE block): ${error.message}`, { code: "certificate" });
  }
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(passphrase ? { key: keyPem, passphrase: String(passphrase) } : { key: keyPem });
  } catch (error) {
    const hint = /passphrase|bad decrypt|password/i.test(error.message)
      ? "the key is encrypted and the passphrase is missing or wrong"
      : "expected PEM with a BEGIN PRIVATE KEY or BEGIN RSA PRIVATE KEY block";
    throw new GraphError(`The private key could not be read (${hint}): ${error.message}`, { code: "certificate" });
  }
  if (!x509.checkPrivateKey(privateKey)) {
    throw new GraphError("The private key does not match the certificate.", { code: "certificate" });
  }
  const notAfter = Date.parse(x509.validTo);
  return {
    cert: x509,
    key: privateKey,
    thumbprint: x509.fingerprint.replace(/:/g, ""),
    subject: x509.subject,
    notAfter: Number.isFinite(notAfter) ? Math.floor(notAfter / 1000) : null,
    expired: Number.isFinite(notAfter) && notAfter < Date.now()
  };
}

/** A secret-free description of a certificate for the UI, or the error if it is unusable. */
function certificateInfo(certificate) {
  if (!certificate || !certificate.cert) return null;
  try {
    const loaded = loadCertificate(certificate);
    return { thumbprint: loaded.thumbprint, subject: loaded.subject, notAfter: loaded.notAfter, expired: loaded.expired, error: null };
  } catch (error) {
    return { thumbprint: null, subject: null, notAfter: null, expired: false, error: error.message };
  }
}

/** The signed JWT Entra accepts instead of a client secret. Valid for ten minutes. */
function buildClientAssertion({ clientId, tenantId, loginBase, certificate, now = Date.now }) {
  const loaded = loadCertificate(certificate);
  const seconds = Math.floor(now() / 1000);
  const header = {
    alg: "RS256",
    typ: "JWT",
    x5t: base64url(Buffer.from(loaded.thumbprint, "hex"))
  };
  const claims = {
    aud: `${loginBase}/${tenantId}/oauth2/v2.0/token`,
    iss: clientId,
    sub: clientId,
    jti: crypto.randomUUID(),
    nbf: seconds - 60,
    exp: seconds + 10 * 60
  };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
  const signature = crypto.sign("sha256", Buffer.from(signingInput), loaded.key);
  return `${signingInput}.${base64url(signature)}`;
}

/** True when the config carries a usable credential of either kind. */
function hasCredential(cfg) {
  return Boolean(cfg.clientSecret || (cfg.certificate && cfg.certificate.cert));
}

/**
 * Reads the client's settings from the environment. Everything is optional so the
 * app can start unconfigured and say so in the UI.
 */
function configFromEnv(env = process.env) {
  // A certificate can be given as files (GRAPH_CERT_FILE, optionally GRAPH_KEY_FILE when
  // the key is not in the same file) or inline PEM (GRAPH_CERT_PEM / GRAPH_KEY_PEM).
  // Read errors are kept, not thrown, so the app still starts and can say what is wrong.
  let certificate = null;
  let certificateError = null;
  const readPem = (file) => fs.readFileSync(file, "utf8");
  try {
    const cert = env.GRAPH_CERT_FILE ? readPem(env.GRAPH_CERT_FILE) : env.GRAPH_CERT_PEM || "";
    const key = env.GRAPH_KEY_FILE ? readPem(env.GRAPH_KEY_FILE) : env.GRAPH_KEY_PEM || "";
    if (cert) {
      certificate = { cert, key, passphrase: env.GRAPH_KEY_PASSPHRASE || "" };
    }
  } catch (error) {
    certificateError = `Could not read the certificate files: ${error.message}`;
  }
  return {
    tenantId: env.GRAPH_TENANT_ID || "",
    clientId: env.GRAPH_CLIENT_ID || "",
    clientSecret: env.GRAPH_CLIENT_SECRET || "",
    certificate,
    certificateError,
    mailbox: env.DMARC_MAILBOX || "",
    folder: env.DMARC_FOLDER || "Inbox",
    loginBase: env.GRAPH_LOGIN_BASE || DEFAULT_LOGIN_BASE,
    graphBase: env.GRAPH_API_BASE || DEFAULT_GRAPH_BASE
  };
}

function createGraphClient(config, { fetchImpl = globalThis.fetch, logger = console } = {}) {
  const cfg = { loginBase: DEFAULT_LOGIN_BASE, graphBase: DEFAULT_GRAPH_BASE, folder: "Inbox", ...config };
  let token = null; // { value, expiresAt (ms) }

  function isConfigured() {
    return Boolean(cfg.tenantId && cfg.clientId && hasCredential(cfg) && cfg.mailbox);
  }

  /** "certificate" when one is configured, else "secret". A certificate wins if both are set. */
  function authMethod() {
    return cfg.certificate && cfg.certificate.cert ? "certificate" : "secret";
  }

  function missingSettings() {
    const missing = [];
    if (!cfg.tenantId) missing.push("GRAPH_TENANT_ID");
    if (!cfg.clientId) missing.push("GRAPH_CLIENT_ID");
    if (!hasCredential(cfg)) missing.push("GRAPH_CLIENT_SECRET or GRAPH_CERT_FILE");
    if (!cfg.mailbox) missing.push("DMARC_MAILBOX");
    return missing;
  }

  /** Public, secret-free view of the configuration for the status endpoint. */
  function describe() {
    const method = authMethod();
    return {
      configured: isConfigured(),
      missing: missingSettings(),
      tenantId: cfg.tenantId || null,
      clientId: cfg.clientId || null,
      mailbox: cfg.mailbox || null,
      folder: cfg.folder || "Inbox",
      authMethod: method,
      certificate: method === "certificate" ? certificateInfo(cfg.certificate) : null,
      certificateError: cfg.certificateError || null
    };
  }

  async function getToken() {
    if (token && token.expiresAt - Date.now() > 60 * 1000) {
      return token.value;
    }
    if (!isConfigured()) {
      throw new GraphError(`Microsoft Graph is not configured. Set ${missingSettings().join(", ")}.`, { code: "not_configured" });
    }

    if (cfg.certificateError) {
      throw new GraphError(cfg.certificateError, { code: "certificate" });
    }
    const body = new URLSearchParams({
      client_id: cfg.clientId,
      scope: "https://graph.microsoft.com/.default",
      grant_type: "client_credentials"
    });
    if (authMethod() === "certificate") {
      // Throws a GraphError with code "certificate" when the PEM is unusable.
      body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
      body.set("client_assertion", buildClientAssertion({
        clientId: cfg.clientId,
        tenantId: cfg.tenantId,
        loginBase: cfg.loginBase,
        certificate: cfg.certificate
      }));
    } else {
      body.set("client_secret", cfg.clientSecret);
    }

    let res;
    try {
      res = await fetchImpl(`${cfg.loginBase}/${encodeURIComponent(cfg.tenantId)}/oauth2/v2.0/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString()
      });
    } catch (error) {
      throw new GraphError(`Could not reach the Microsoft sign-in service: ${describeFetchError(error)}`, { code: "network" });
    }

    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.access_token) {
      const detail = data.error_description || data.error || `HTTP ${res.status}`;
      throw new GraphError(`Token request failed: ${detail}`, { status: res.status, code: data.error || "token" });
    }

    token = { value: data.access_token, expiresAt: Date.now() + (Number(data.expires_in) || 3600) * 1000 };
    return token.value;
  }

  function explain(status, code, message) {
    if (status === 401) {
      token = null;
      return `Graph rejected the token (${code || 401}). ${message || ""}`.trim();
    }
    if (status === 403) {
      return `Access to mailbox ${cfg.mailbox} was denied (${code || 403}). Check that the app registration has ` +
        "Mail.Read as an Application permission with admin consent granted, and that any application access " +
        "policy in Exchange Online includes this mailbox.";
    }
    if (status === 404) {
      return `Graph could not find the resource (${code || 404}): ${message || ""}. Check DMARC_MAILBOX and DMARC_FOLDER.`;
    }
    return `Graph request failed (${status}${code ? " " + code : ""}): ${message || ""}`;
  }

  /** GET (by default) a Graph URL and return the parsed JSON body, retrying throttles. */
  async function graphFetch(url, { method = "GET", headers = {}, raw = false } = {}) {
    const fullUrl = url.startsWith("http") ? url : `${cfg.graphBase}${url}`;

    for (let attempt = 0; ; attempt += 1) {
      const bearer = await getToken();
      let res;
      try {
        res = await fetchImpl(fullUrl, {
          method,
          headers: { Authorization: `Bearer ${bearer}`, Accept: raw ? "*/*" : "application/json", ...headers }
        });
      } catch (error) {
        if (attempt < MAX_RETRIES) {
          await sleep(1000 * (attempt + 1));
          continue;
        }
        throw new GraphError(`Could not reach Microsoft Graph: ${describeFetchError(error)}`, { code: "network" });
      }

      if (res.status === 429 || res.status === 503 || res.status === 504) {
        if (attempt >= MAX_RETRIES) {
          throw new GraphError(`Graph kept throttling (${res.status}) after ${MAX_RETRIES} retries.`, { status: res.status, code: "throttled", retryable: true });
        }
        const retryAfter = Number(res.headers.get("retry-after"));
        const waitMs = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 2000 * (attempt + 1);
        logger.warn?.(`Graph ${res.status}; retrying in ${Math.round(waitMs / 1000)}s`);
        await sleep(waitMs);
        continue;
      }

      if (res.status === 401 && attempt === 0) {
        token = null; // expired early or revoked: fetch a fresh one and try once more
        continue;
      }

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        const err = data.error || {};
        throw new GraphError(explain(res.status, err.code, err.message), { status: res.status, code: err.code });
      }

      if (raw) {
        return Buffer.from(await res.arrayBuffer());
      }
      return res.json();
    }
  }

  const userBase = () => `/users/${encodeURIComponent(cfg.mailbox)}`;

  /**
   * Resolves a folder display name (or "Parent/Child" path) to a folder id.
   * "Inbox" maps to the well-known name and needs no lookup.
   */
  async function resolveFolderId(folderName = cfg.folder) {
    const name = String(folderName || "Inbox").trim();
    if (!name || name.toLowerCase() === "inbox") {
      return "inbox";
    }

    const segments = name.split("/").map((s) => s.trim()).filter(Boolean);
    let parentId = null;
    for (const segment of segments) {
      const base = parentId ? `${userBase()}/mailFolders/${encodeURIComponent(parentId)}/childFolders` : `${userBase()}/mailFolders`;
      const data = await graphFetch(`${base}?$filter=displayName eq ${encodeURIComponent(odataString(segment))}&$select=id,displayName`);
      const match = (data.value || [])[0];
      if (!match) {
        throw new GraphError(`Mail folder "${name}" was not found in ${cfg.mailbox} (no folder named "${segment}").`, { status: 404, code: "folder_not_found" });
      }
      parentId = match.id;
    }
    return parentId;
  }

  /**
   * Yields messages with attachments received at or after `since` (a Date or ms),
   * oldest first, following @odata.nextLink across pages.
   *
   * Only receivedDateTime is filtered server-side. Adding "hasAttachments eq true"
   * to a query that also sorts on receivedDateTime makes Exchange answer
   * 400 InefficientFilter ("restriction or sort order is too complex") on many
   * mailboxes, so attachment-less messages are dropped here instead.
   */
  async function* listMessages({ folderId = "inbox", since } = {}) {
    const sinceIso = new Date(since || 0).toISOString().replace(/\.\d{3}Z$/, "Z");
    const filter = `receivedDateTime ge ${sinceIso}`;
    let url = `${userBase()}/mailFolders/${encodeURIComponent(folderId)}/messages` +
      `?$filter=${encodeURIComponent(filter)}` +
      `&$select=id,internetMessageId,subject,receivedDateTime,from,hasAttachments` +
      `&$orderby=receivedDateTime asc&$top=${PAGE_SIZE}`;

    while (url) {
      const data = await graphFetch(url);
      for (const message of data.value || []) {
        if (message.hasAttachments === false) {
          continue; // nothing to unpack; a report always arrives as an attachment
        }
        yield {
          id: message.id,
          internetMessageId: message.internetMessageId || null,
          subject: message.subject || "",
          receivedAt: message.receivedDateTime,
          from: message.from?.emailAddress?.address || null
        };
      }
      url = data["@odata.nextLink"] || null;
    }
  }

  /** Returns the file attachments of a message with their bytes decoded. */
  async function getAttachments(messageId) {
    const data = await graphFetch(`${userBase()}/messages/${encodeURIComponent(messageId)}/attachments`);
    const out = [];
    for (const att of data.value || []) {
      if (att["@odata.type"] !== "#microsoft.graph.fileAttachment") {
        continue; // item or reference attachments are never reports
      }
      let bytes;
      if (typeof att.contentBytes === "string") {
        bytes = Buffer.from(att.contentBytes, "base64");
      } else {
        // Large attachments come without contentBytes; fetch the raw value instead.
        bytes = await graphFetch(`${userBase()}/messages/${encodeURIComponent(messageId)}/attachments/${encodeURIComponent(att.id)}/$value`, { raw: true });
      }
      out.push({ id: att.id, name: att.name || "", contentType: att.contentType || "", size: att.size || bytes.length, bytes });
    }
    return out;
  }

  /** The raw MIME of a message (for forensic reports, whose parts are not ordinary attachments). */
  async function getMime(messageId) {
    return graphFetch(`${userBase()}/messages/${encodeURIComponent(messageId)}/$value`, { raw: true });
  }

  /** Token + folder lookup, for the Settings panel. Never throws; returns { ok, detail }. */
  async function testConnection() {
    if (!isConfigured()) {
      return { ok: false, detail: `Not configured. Missing: ${missingSettings().join(", ")}.` };
    }
    try {
      await getToken();
    } catch (error) {
      return { ok: false, stage: "token", detail: error.message };
    }
    try {
      const folderId = await resolveFolderId();
      const data = await graphFetch(`${userBase()}/mailFolders/${encodeURIComponent(folderId)}?$select=id,displayName,totalItemCount`);
      return {
        ok: true,
        stage: "folder",
        detail: `Signed in. Folder "${data.displayName}" in ${cfg.mailbox} holds ${data.totalItemCount} item(s).`,
        folder: data.displayName,
        totalItemCount: data.totalItemCount
      };
    } catch (error) {
      return { ok: false, stage: "mailbox", detail: error.message };
    }
  }

  return {
    config: cfg,
    isConfigured,
    describe,
    getToken,
    authMethod,
    graphFetch,
    resolveFolderId,
    listMessages,
    getAttachments,
    getMime,
    testConnection
  };
}

module.exports = { createGraphClient, configFromEnv, loadCertificate, certificateInfo, buildClientAssertion, GraphError };
