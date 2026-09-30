/**
 * The shape every non-Graph mail source shares. IMAP, POP3, Gmail and S3 all
 * hand over whole RFC 822 messages, so each source only has to say how to open
 * a session, list message keys and fetch one raw message. This adapter turns
 * that into the client interface the sync engine already uses for Microsoft
 * Graph: listMessages / getAttachments / getMime / testConnection.
 *
 * Listing is lazy on purpose. The sync skips messages it has seen before it
 * asks for attachments, so a raw message is only downloaded for new ones; the
 * subject, sender and date are filled in on the yielded message object at that
 * point, which is when the sync reads them.
 */
const { extractMessage } = require("./mime-attachments");

class SourceError extends Error {
  /**
   * @param fatal stop syncing this mailbox (bad credentials, host unreachable), as opposed to one bad message
   * @param stage where it failed, for the connection test: connection | login | folder | list | fetch
   */
  constructor(message, { code = "source", fatal = false, stage = "connection" } = {}) {
    super(message);
    this.name = "SourceError";
    this.code = code;
    this.fatal = fatal;
    this.stage = stage;
  }
}

/**
 * @param type     "imap" | "pop3" | "gws" | "ses"
 * @param idPrefix makes message ids unique across mailboxes, e.g. "imap:ab12cd34:"
 * @param open     async () => session { list({ since }) async iterable of { key, receivedAt?, subject?, from? },
 *                                        fetchRaw(key) => Buffer | { raw, receivedAt }, close() }
 * @param test     async () => a sentence describing what the source can see
 */
function createRawSource({ type, idPrefix, config = {}, isConfigured, missing = () => [], describe = () => ({}), authMethod = () => "password", open, test }) {
  let active = null;            // the session of a listing in progress
  let cached = null;            // { id, raw, parsed } for the message being processed
  const pending = new Map();    // id -> the message object yielded to the sync

  function keyOf(id) {
    return String(id).startsWith(idPrefix) ? String(id).slice(idPrefix.length) : String(id);
  }

  async function load(id) {
    if (cached && cached.id === id) return cached;
    const session = active || await open();
    try {
      const fetched = await session.fetchRaw(keyOf(id));
      const raw = Buffer.isBuffer(fetched) ? fetched : fetched.raw;
      const parsed = extractMessage(raw);
      const receivedAt = (!Buffer.isBuffer(fetched) && fetched.receivedAt) || null;
      cached = { id, raw, parsed };
      const message = pending.get(id);
      if (message) {
        message.subject = message.subject || parsed.subject;
        message.from = message.from || parsed.from;
        message.internetMessageId = parsed.messageId;
        if (!message.receivedAt) {
          const seconds = receivedAt || parsed.date || Math.floor(Date.now() / 1000);
          message.receivedAt = new Date(seconds * 1000).toISOString();
        }
      }
      return cached;
    } finally {
      if (session !== active) await session.close().catch(() => {});
    }
  }

  async function* listMessages({ since } = {}) {
    const session = await open();
    active = session;
    try {
      const sinceSeconds = since ? Math.floor(since / 1000) : 0;
      for await (const entry of session.list({ since: sinceSeconds })) {
        const message = {
          id: `${idPrefix}${entry.key}`,
          subject: entry.subject || null,
          from: entry.from || null,
          receivedAt: entry.receivedAt ? new Date(entry.receivedAt * 1000).toISOString() : null,
          internetMessageId: null,
          hasAttachments: true
        };
        pending.set(message.id, message);
        try {
          yield message;
        } finally {
          pending.delete(message.id);
          if (cached && cached.id === message.id) cached = null;
        }
      }
    } finally {
      active = null;
      await session.close().catch(() => {});
    }
  }

  async function getAttachments(id) {
    return (await load(id)).parsed.attachments;
  }

  async function getMime(id) {
    return (await load(id)).raw.toString("latin1");
  }

  async function testConnection() {
    if (!isConfigured()) {
      return { ok: false, stage: "config", detail: `Missing: ${missing().join(", ")}.` };
    }
    try {
      return { ok: true, stage: "done", detail: await test() };
    } catch (error) {
      return { ok: false, stage: error.stage || "connection", detail: error.message };
    }
  }

  return {
    type,
    config,
    isConfigured,
    describe: () => ({ type, configured: isConfigured(), missing: missing(), ...describe() }),
    authMethod,
    // No folder lookup step for these; the folder or label is resolved when the session opens.
    resolveFolderId: async () => null,
    listMessages,
    getAttachments,
    getMime,
    testConnection
  };
}

module.exports = { createRawSource, SourceError };
