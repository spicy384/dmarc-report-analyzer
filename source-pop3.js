/**
 * POP3 mailbox source. POP3 is simple enough to speak directly: greeting,
 * optional STLS, USER/PASS, UIDL to list, RETR to download, QUIT. Nothing is
 * ever deleted (no DELE), so the mailbox is left exactly as it was.
 *
 * POP3 has no folders and no dates in the listing, so every message not seen
 * before is downloaded once, whatever its age; the unique id (UIDL) is what
 * stops it being downloaded again.
 */
const net = require("net");
const tls = require("tls");
const { createRawSource, SourceError } = require("./source-raw");

/** A line-oriented reader over a socket, with a timeout on every wait. */
function createConnection({ host, port, security, tlsVerify, timeoutMs }) {
  let socket = null;
  let chunks = [];      // received and not yet consumed, joined only when a reader looks
  let buffered = 0;
  let waiter = null;
  let failure = null;

  function attach(sock) {
    socket = sock;
    socket.on("data", (chunk) => {
      chunks.push(chunk);
      buffered += chunk.length;
      if (waiter) waiter.check(chunk);
    });
    socket.on("error", (error) => {
      failure = error;
      if (waiter) waiter.fail(error);
    });
    socket.on("close", () => {
      if (!failure) failure = new Error("connection closed by the server");
      if (waiter) waiter.fail(failure);
    });
  }

  function wait(extract) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        waiter = null;
        reject(Object.assign(new Error(`timed out after ${Math.round(timeoutMs / 1000)}s`), { code: "ETIMEDOUT" }));
      }, timeoutMs);
      const finish = (fn, value) => {
        clearTimeout(timer);
        waiter = null;
        fn(value);
      };
      waiter = {
        check: (chunk = null) => {
          const hit = extract(chunk);
          if (hit !== null) finish(resolve, hit);
        },
        fail: (error) => finish(reject, error)
      };
      if (failure) return waiter.fail(failure);
      waiter.check();
    });
  }

  /** Everything buffered, as one Buffer. */
  function joined() {
    if (chunks.length > 1) chunks = [Buffer.concat(chunks, buffered)];
    return chunks[0] || Buffer.alloc(0);
  }

  /** Drops the first `upTo` bytes of `buf` (the joined buffer) from what is buffered. */
  function consume(buf, upTo) {
    const rest = buf.subarray(upTo);
    chunks = rest.length ? [rest] : [];
    buffered = rest.length;
  }

  function readLine() {
    return wait(() => {
      const buf = joined();
      const end = buf.indexOf("\r\n");
      if (end < 0) return null;
      const line = buf.subarray(0, end).toString("latin1");
      consume(buf, end + 2);
      return line;
    });
  }

  const END = Buffer.from("\r\n.\r\n", "latin1");

  /** Could the terminator end inside this chunk? If not, a large body need not be joined and searched yet. */
  function mayComplete(chunk) {
    if (chunk.indexOf(END) >= 0) return true;
    for (let k = 1; k < END.length; k += 1) {
      if (chunk.length >= k && chunk.subarray(0, k).equals(END.subarray(END.length - k))) return true;
    }
    return false;
  }

  /** A multi-line response body: everything up to a line holding a single dot, dot-unstuffed. */
  function readMultiline() {
    let scanned = 0; // bytes already searched for the terminator
    return wait((chunk) => {
      if (chunk && chunks.length > 1 && !mayComplete(chunk)) return null;
      const buf = joined();
      const startsWithEnd = buf.length >= 3 && buf[0] === 0x2e && buf[1] === 0x0d && buf[2] === 0x0a;
      const end = startsWithEnd ? -2 : buf.indexOf(END, Math.max(0, scanned - END.length));
      if (!startsWithEnd && end < 0) {
        scanned = buf.length;
        return null;
      }
      const body = startsWithEnd ? Buffer.alloc(0) : buf.subarray(0, end + 2);
      consume(buf, startsWithEnd ? 3 : end + 5);
      // Lines that began with a dot were sent with it doubled.
      return Buffer.from(body.toString("latin1").replace(/(^|\r\n)\.\./g, "$1."), "latin1");
    });
  }

  function connect() {
    return new Promise((resolve, reject) => {
      const onError = (error) => reject(error);
      const options = { host, port, servername: host, rejectUnauthorized: tlsVerify !== false };
      const sock = security === "tls" ? tls.connect(options) : net.connect({ host, port });
      sock.setTimeout(timeoutMs, () => sock.destroy(Object.assign(new Error("connection timed out"), { code: "ETIMEDOUT" })));
      sock.once("error", onError);
      sock.once(security === "tls" ? "secureConnect" : "connect", () => {
        sock.removeListener("error", onError);
        sock.setTimeout(0);
        attach(sock);
        resolve();
      });
    });
  }

  function upgradeToTls() {
    return new Promise((resolve, reject) => {
      const plain = socket;
      plain.removeAllListeners("data");
      plain.removeAllListeners("error");
      plain.removeAllListeners("close");
      const secure = tls.connect({ socket: plain, servername: host, rejectUnauthorized: tlsVerify !== false });
      secure.once("error", reject);
      secure.once("secureConnect", () => {
        secure.removeListener("error", reject);
        chunks = [];
        buffered = 0;
        attach(secure);
        resolve();
      });
    });
  }

  async function command(text) {
    socket.write(`${text}\r\n`);
    const line = await readLine();
    if (!line.startsWith("+OK")) {
      throw Object.assign(new Error(line.replace(/^-ERR\s*/, "") || "command refused"), { pop3: true, command: text.split(" ")[0] });
    }
    return line;
  }

  function end() {
    if (socket) socket.destroy();
  }

  return { connect, upgradeToTls, readLine, readMultiline, command, end };
}

/**
 * @param cfg { host, port, security: "tls" | "starttls" | "none", username, password, tlsVerify }
 */
function createPop3Source(cfg, { idPrefix = "pop3:", timeoutMs = 30000 } = {}) {
  const config = { security: "tls", tlsVerify: true, ...cfg };
  config.port = Number(config.port) || (config.security === "tls" ? 995 : 110);

  const isConfigured = () => Boolean(config.host && config.username && config.password);
  const missing = () => [!config.host && "host", !config.username && "username", !config.password && "password"].filter(Boolean);

  async function open() {
    if (!isConfigured()) {
      throw new SourceError(`POP3 is not configured: missing ${missing().join(", ")}.`, { code: "not_configured", fatal: true, stage: "config" });
    }
    const conn = createConnection({ host: config.host, port: config.port, security: config.security, tlsVerify: config.tlsVerify, timeoutMs });
    try {
      await conn.connect();
      const greeting = await conn.readLine();
      if (!greeting.startsWith("+OK")) throw new Error(`unexpected greeting: ${greeting}`);
      if (config.security === "starttls") {
        await conn.command("STLS");
        await conn.upgradeToTls();
      }
    } catch (error) {
      conn.end();
      const tlsProblem = /certificate|self.signed|CERT_/i.test(`${error.code || ""} ${error.message}`);
      throw new SourceError(tlsProblem
        ? `TLS certificate problem talking to ${config.host}: ${error.message}. If the server uses a private certificate, turn off certificate checking for this mailbox.`
        : `Could not reach ${config.host}:${config.port} (${error.code || error.message}).`, { code: tlsProblem ? "tls" : "network", fatal: true, stage: "connection" });
    }
    try {
      await conn.command(`USER ${config.username}`);
      await conn.command(`PASS ${config.password}`);
    } catch (error) {
      conn.end();
      throw new SourceError(`The POP3 server rejected the sign-in for ${config.username}${error.pop3 ? `: ${error.message}` : ""}. Check the username and password; many providers need an app password when two-factor is on.`, { code: "auth", fatal: true, stage: "login" });
    }

    // UIDL maps this session's message numbers to ids that are stable across sessions.
    let numbers = null;
    async function uidl() {
      if (numbers) return numbers;
      try {
        await conn.command("UIDL");
      } catch (error) {
        throw new SourceError(`The POP3 server does not support UIDL, which is needed to tell messages apart: ${error.message}`, { code: "uidl", fatal: true, stage: "list" });
      }
      const body = (await conn.readMultiline()).toString("latin1");
      numbers = new Map();
      for (const line of body.split("\r\n")) {
        const m = line.match(/^(\d+)\s+(\S+)/);
        if (m) numbers.set(m[2], Number(m[1]));
      }
      return numbers;
    }

    return {
      uidl,
      async *list() {
        const map = await uidl();
        // Oldest first, as the server numbers them.
        for (const [id] of [...map.entries()].sort((a, b) => a[1] - b[1])) {
          yield { key: id };
        }
      },
      async fetchRaw(key) {
        const map = await uidl();
        const number = map.get(String(key));
        if (!number) {
          throw new SourceError(`Message ${key} is no longer in the mailbox.`, { code: "gone", stage: "fetch" });
        }
        try {
          await conn.command(`RETR ${number}`);
          return await conn.readMultiline();
        } catch (error) {
          throw new SourceError(`Could not download message ${number}: ${error.message}`, { code: "fetch", stage: "fetch" });
        }
      },
      async close() {
        try {
          await conn.command("QUIT");
        } catch {
          // Closing anyway.
        }
        conn.end();
      }
    };
  }

  async function test() {
    const session = await open();
    try {
      const map = await session.uidl();
      return `Signed in to ${config.host} as ${config.username}; the mailbox holds ${map.size} message${map.size === 1 ? "" : "s"}.`;
    } finally {
      await session.close();
    }
  }

  return createRawSource({
    type: "pop3",
    idPrefix,
    config,
    isConfigured,
    missing,
    describe: () => ({ host: config.host, port: config.port, security: config.security, username: config.username }),
    authMethod: () => "password",
    open,
    test
  });
}

module.exports = { createPop3Source };
