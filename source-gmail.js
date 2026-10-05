/**
 * Google Workspace mailbox source through the Gmail API, unattended: a service
 * account with domain-wide delegation impersonates the mailbox user with the
 * read-only Gmail scope. No Google SDK: the token is a signed JWT exchanged at
 * the token endpoint (the same client-assertion idea as the Entra certificate
 * path), and the API calls are plain HTTPS.
 *
 * Messages are fetched in raw form and handed to the shared MIME extractor.
 */
const { describeFetchError } = require("./net-errors");
const crypto = require("crypto");
const { createRawSource, SourceError } = require("./source-raw");

const SCOPE = "https://www.googleapis.com/auth/gmail.readonly";
const DEFAULT_API_BASE = "https://gmail.googleapis.com";
const DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";

function base64url(input) {
  return Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Accepts the service account key as the JSON text Google downloads, or an object. Throws SourceError if unusable. */
function parseServiceAccount(key) {
  let parsed = key;
  if (typeof key === "string") {
    try {
      parsed = JSON.parse(key);
    } catch {
      throw new SourceError("The service account key is not valid JSON. Paste the whole .json file Google gave you.", { code: "service_account", fatal: true, stage: "config" });
    }
  }
  if (!parsed || typeof parsed !== "object" || !parsed.client_email || !parsed.private_key) {
    throw new SourceError("The service account key is missing client_email or private_key. It must be a service account key, not an OAuth client secret.", { code: "service_account", fatal: true, stage: "config" });
  }
  try {
    crypto.createPrivateKey(parsed.private_key);
  } catch (error) {
    throw new SourceError(`The private_key in the service account key could not be read: ${error.message}`, { code: "service_account", fatal: true, stage: "config" });
  }
  return parsed;
}

/**
 * @param cfg { serviceAccountKey (JSON text or object), mailbox (the user to read), folder (a label name, optional), apiBase }
 */
function createGmailSource(cfg, { idPrefix = "gws:", fetchImpl = globalThis.fetch, now = Date.now } = {}) {
  const config = { apiBase: DEFAULT_API_BASE, ...cfg };
  const user = config.mailbox;
  let token = null; // { value, expiresAt }

  const isConfigured = () => Boolean(config.serviceAccountKey && user);
  const missing = () => [!config.serviceAccountKey && "service account key", !user && "mailbox address"].filter(Boolean);

  function account() {
    return parseServiceAccount(config.serviceAccountKey);
  }

  async function getToken() {
    if (token && token.expiresAt - now() > 60 * 1000) return token.value;
    const sa = account();
    const tokenUri = config.tokenUri || sa.token_uri || DEFAULT_TOKEN_URI;
    const iat = Math.floor(now() / 1000);
    const header = { alg: "RS256", typ: "JWT", ...(sa.private_key_id ? { kid: sa.private_key_id } : {}) };
    const claims = { iss: sa.client_email, sub: user, scope: SCOPE, aud: tokenUri, iat, exp: iat + 3600 };
    const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
    const assertion = `${signingInput}.${base64url(crypto.sign("sha256", Buffer.from(signingInput), sa.private_key))}`;

    let res;
    try {
      res = await fetchImpl(tokenUri, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }).toString()
      });
    } catch (error) {
      throw new SourceError(`Could not reach Google's token service: ${describeFetchError(error)}`, { code: "network", fatal: true, stage: "connection" });
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.access_token) {
      const reason = data.error_description || data.error || `HTTP ${res.status}`;
      const hint = /unauthorized_client|access_denied/.test(`${data.error} ${data.error_description}`)
        ? ` The service account's client ID needs domain-wide delegation for the scope ${SCOPE} in the Google Admin console (Security > API controls > Domain-wide delegation).`
        : /invalid_grant/.test(String(data.error)) ? ` Check that ${user} is a real user in the domain and the server clock is correct.` : "";
      throw new SourceError(`Google refused the token request: ${reason}.${hint}`, { code: "token", fatal: true, stage: "login" });
    }
    token = { value: data.access_token, expiresAt: now() + (Number(data.expires_in) || 3600) * 1000 };
    return token.value;
  }

  async function api(pathAndQuery) {
    const bearer = await getToken();
    let res;
    try {
      res = await fetchImpl(`${config.apiBase}/gmail/v1/users/${encodeURIComponent(user)}${pathAndQuery}`, { headers: { Authorization: `Bearer ${bearer}` } });
    } catch (error) {
      throw new SourceError(`Could not reach the Gmail API: ${describeFetchError(error)}`, { code: "network", fatal: true, stage: "connection" });
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const message = (data.error && (data.error.message || data.error.status)) || `HTTP ${res.status}`;
      if (res.status === 401) token = null;
      const fatal = res.status === 401 || res.status === 403 || res.status === 404;
      const hint = res.status === 403 && /has not been used|disabled/i.test(message) ? " Enable the Gmail API for the service account's Google Cloud project." : "";
      throw new SourceError(`Gmail API error (${res.status}): ${message}.${hint}`, { code: res.status === 429 ? "throttled" : "api", fatal, stage: "list" });
    }
    return data;
  }

  async function open() {
    if (!isConfigured()) {
      throw new SourceError(`Google Workspace is not configured: missing ${missing().join(", ")}.`, { code: "not_configured", fatal: true, stage: "config" });
    }
    await getToken();
    return {
      async *list({ since }) {
        // Gmail's search takes epoch seconds for after:. A label narrows to where a filter files the reports.
        const q = [since ? `after:${since}` : "", config.folder ? `label:${String(config.folder).replace(/\s+/g, "-")}` : ""].filter(Boolean).join(" ");
        let pageToken = "";
        do {
          const params = new URLSearchParams({ maxResults: "100", includeSpamTrash: "false" });
          if (q) params.set("q", q);
          if (pageToken) params.set("pageToken", pageToken);
          const page = await api(`/messages?${params.toString()}`);
          // Newest first from the API; oldest first reads better in the run log.
          for (const m of [...(page.messages || [])].reverse()) {
            yield { key: m.id };
          }
          pageToken = page.nextPageToken || "";
        } while (pageToken);
      },
      async fetchRaw(key) {
        let data;
        try {
          data = await api(`/messages/${encodeURIComponent(key)}?format=raw`);
        } catch (error) {
          if (error.fatal && !/404/.test(error.message)) throw error;
          throw new SourceError(`Could not fetch message ${key}: ${error.message}`, { code: "fetch", stage: "fetch" });
        }
        if (!data.raw) {
          throw new SourceError(`Message ${key} came back without content.`, { code: "fetch", stage: "fetch" });
        }
        return { raw: Buffer.from(data.raw, "base64url"), receivedAt: data.internalDate ? Math.floor(Number(data.internalDate) / 1000) : null };
      },
      async close() {}
    };
  }

  async function test() {
    await getToken();
    const profile = await api("/profile");
    return `Reading ${profile.emailAddress || user} as ${account().client_email}; the mailbox holds ${profile.messagesTotal ?? "an unknown number of"} messages${config.folder ? `, filtered to the label "${config.folder}"` : ""}.`;
  }

  return createRawSource({
    type: "gws",
    idPrefix,
    config,
    isConfigured,
    missing,
    describe: () => {
      let email = null;
      try {
        email = account().client_email;
      } catch {
        email = null;
      }
      return { mailbox: user, serviceAccount: email, label: config.folder || null };
    },
    authMethod: () => "service account",
    open,
    test
  });
}

module.exports = { createGmailSource, parseServiceAccount, SCOPE };
