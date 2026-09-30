/**
 * IMAP mailbox source, for any provider that offers IMAP with a username and
 * password (or app password): Dovecot, Fastmail, Gmail with an app password,
 * hosted cPanel mail and so on. The protocol work is done by imapflow; this
 * file maps a mailbox configuration to the raw-source session shape.
 *
 * The folder is opened read-only, so nothing is marked as read or moved.
 */
const { ImapFlow } = require("imapflow");
const { createRawSource, SourceError } = require("./source-raw");

function describeImapError(error, cfg) {
  if (error instanceof SourceError) return error;
  if (error.authenticationFailed || /AUTHENTICATIONFAILED|Invalid credentials|LOGIN failed/i.test(`${error.responseText || ""} ${error.message}`)) {
    return new SourceError(`The IMAP server rejected the sign-in for ${cfg.username}. Check the username and password; many providers need an app password when two-factor is on.`, { code: "auth", fatal: true, stage: "login" });
  }
  if (["ENOTFOUND", "ECONNREFUSED", "ETIMEDOUT", "EHOSTUNREACH", "ECONNRESET"].includes(error.code)) {
    return new SourceError(`Could not reach ${cfg.host}:${cfg.port} (${error.code}).`, { code: "network", fatal: true, stage: "connection" });
  }
  if (/certificate|self.signed|CERT_/i.test(`${error.code || ""} ${error.message}`)) {
    return new SourceError(`TLS certificate problem talking to ${cfg.host}: ${error.message}. If the server uses a private certificate, turn off certificate checking for this mailbox.`, { code: "tls", fatal: true, stage: "connection" });
  }
  return new SourceError(`IMAP error: ${error.responseText || error.message}`, { code: "imap", fatal: true, stage: "connection" });
}

/**
 * @param cfg { host, port, security: "tls" | "starttls" | "none", username, password, folder, tlsVerify }
 * @param ImapClient injectable for tests; defaults to imapflow's ImapFlow
 */
function createImapSource(cfg, { idPrefix = "imap:", ImapClient = ImapFlow } = {}) {
  const config = { port: cfg.security === "tls" || !cfg.security ? 993 : 143, security: "tls", folder: "INBOX", tlsVerify: true, ...cfg };
  config.port = Number(config.port) || (config.security === "tls" ? 993 : 143);
  const folder = config.folder || "INBOX";

  const isConfigured = () => Boolean(config.host && config.username && config.password);
  const missing = () => [!config.host && "host", !config.username && "username", !config.password && "password"].filter(Boolean);

  async function open() {
    if (!isConfigured()) {
      throw new SourceError(`IMAP is not configured: missing ${missing().join(", ")}.`, { code: "not_configured", fatal: true, stage: "config" });
    }
    const client = new ImapClient({
      host: config.host,
      port: config.port,
      secure: config.security === "tls",
      // imapflow upgrades with STARTTLS on its own when the server offers it; "none" forbids that.
      doSTARTTLS: config.security === "starttls" ? true : config.security === "none" ? false : undefined,
      auth: { user: config.username, pass: config.password },
      tls: { rejectUnauthorized: config.tlsVerify !== false },
      logger: false
    });
    // A dropped connection must not become an unhandled 'error' event.
    if (typeof client.on === "function") client.on("error", () => {});
    let box;
    try {
      await client.connect();
    } catch (error) {
      throw describeImapError(error, config);
    }
    try {
      box = await client.mailboxOpen(folder, { readOnly: true });
    } catch (error) {
      await client.logout().catch(() => {});
      throw new SourceError(`The folder "${folder}" could not be opened: ${error.responseText || error.message}`, { code: "folder_not_found", fatal: true, stage: "folder" });
    }
    const uidValidity = String(box.uidValidity || "0");

    return {
      box,
      async *list({ since }) {
        let uids;
        try {
          // SEARCH SINCE works on whole days by the server's internal date.
          uids = await client.search(since ? { since: new Date(since * 1000) } : { all: true }, { uid: true });
        } catch (error) {
          throw describeImapError(error, config);
        }
        for (const uid of [...(uids || [])].sort((a, b) => a - b)) {
          yield { key: `${uidValidity}:${uid}` };
        }
      },
      async fetchRaw(key) {
        const uid = String(key).split(":")[1];
        let message;
        try {
          message = await client.fetchOne(uid, { source: true, internalDate: true }, { uid: true });
        } catch (error) {
          throw new SourceError(`Could not fetch message ${uid}: ${error.responseText || error.message}`, { code: "fetch", stage: "fetch" });
        }
        if (!message || !message.source) {
          throw new SourceError(`Message ${uid} is no longer in ${folder}.`, { code: "gone", stage: "fetch" });
        }
        const internal = message.internalDate ? Math.floor(new Date(message.internalDate).getTime() / 1000) : null;
        return { raw: Buffer.isBuffer(message.source) ? message.source : Buffer.from(message.source), receivedAt: internal };
      },
      async close() {
        try {
          await client.logout();
        } catch {
          if (typeof client.close === "function") client.close();
        }
      }
    };
  }

  async function test() {
    const session = await open();
    try {
      return `Signed in to ${config.host} as ${config.username}; "${folder}" holds ${session.box.exists ?? "an unknown number of"} messages.`;
    } finally {
      await session.close();
    }
  }

  return createRawSource({
    type: "imap",
    idPrefix,
    config,
    isConfigured,
    missing,
    describe: () => ({ host: config.host, port: config.port, security: config.security, username: config.username, folder }),
    authMethod: () => "password",
    open,
    test
  });
}

module.exports = { createImapSource };
