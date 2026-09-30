/**
 * The non-Graph mail sources: MIME attachment extraction, the raw-source adapter,
 * POP3 against a mock server, IMAP through a fake client, Gmail and S3 against
 * mock HTTP servers, the mailbox store's type handling, and a sync end to end.
 */
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const net = require("net");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const { createChecker } = require("./helpers/assert");
const { extractMessage } = require("../mime-attachments");
const { createRawSource, SourceError } = require("../source-raw");
const { createPop3Source } = require("../source-pop3");
const { createImapSource } = require("../source-imap");
const { createGmailSource, parseServiceAccount, SCOPE } = require("../source-gmail");
const { createS3Source, signV4 } = require("../source-s3");
const { createMailboxStore, TYPES } = require("../mailboxes");
const { openDatabase } = require("../db");
const { createSync } = require("../sync");

const { check, report } = createChecker("sources: MIME, adapter, POP3, IMAP, Gmail, S3, store, sync");

const googleXml = fs.readFileSync(path.join(__dirname, "..", "examples", "google-aggregate.xml"), "utf8");
const microsoftXml = fs.readFileSync(path.join(__dirname, "..", "examples", "microsoft-aggregate.xml"), "utf8");

/** A report email the way receivers send them: text part plus a base64 attachment. */
function makeMessage({ subject = "Report Domain: example.com", from = "noreply-dmarc-support@google.com", date = "Mon, 22 Sep 2025 10:00:00 +0000", name = "report.xml.gz", bytes, messageId = "<m1@reporter.test>" }) {
  const b64 = bytes.toString("base64").replace(/(.{76})/g, "$1\r\n");
  return Buffer.from([
    `From: DMARC Reporter <${from}>`,
    `Subject: ${subject}`,
    `Date: ${date}`,
    `Message-ID: ${messageId}`,
    "MIME-Version: 1.0",
    "Content-Type: multipart/mixed; boundary=\"bnd42\"",
    "",
    "--bnd42",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "This is a DMARC aggregate report.",
    "",
    "--bnd42",
    `Content-Type: application/gzip; name="${name}"`,
    "Content-Transfer-Encoding: base64",
    `Content-Disposition: attachment; filename="${name}"`,
    "",
    b64,
    "--bnd42--",
    ""
  ].join("\r\n"), "latin1");
}

const gzGoogle = zlib.gzipSync(Buffer.from(googleXml, "utf8"));
const gzMicrosoft = zlib.gzipSync(Buffer.from(microsoftXml, "utf8"));
const msgGoogle = makeMessage({ bytes: gzGoogle, messageId: "<g@reporter.test>" });
const msgMicrosoft = makeMessage({ bytes: gzMicrosoft, from: "dmarcreport@microsoft.com", subject: "Report Domain: example.com Submitter: protection.outlook.com", name: "ms!example.com.xml.gz", messageId: "<m@reporter.test>", date: "Tue, 23 Sep 2025 11:00:00 +0000" });

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
}
function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
}

(async () => {
  // === MIME extraction ===
  const ex = extractMessage(msgGoogle);
  check("mime: envelope headers", ex.subject === "Report Domain: example.com" && ex.from === "noreply-dmarc-support@google.com" && ex.messageId === "<g@reporter.test>" && ex.date === Date.parse("2025-09-22T10:00:00Z") / 1000);
  check("mime: attachment bytes survive base64 intact", ex.attachments.length === 1 && ex.attachments[0].name === "report.xml.gz" && ex.attachments[0].bytes.equals(gzGoogle));
  check("mime: the text body is not an attachment", !ex.attachments.some((a) => a.contentType === "text/plain"));

  const single = extractMessage(Buffer.from(["From: a@b.test", "Subject: single", "Content-Type: application/gzip", "Content-Transfer-Encoding: base64", "", gzGoogle.toString("base64"), ""].join("\r\n"), "latin1"));
  check("mime: a message that is itself the attachment", single.attachments.length === 1 && single.attachments[0].bytes.equals(gzGoogle) && /gzip/.test(single.attachments[0].name));

  const rfc2231 = extractMessage(Buffer.from(["From: a@b.test", "Content-Type: multipart/mixed; boundary=x", "", "--x", "Content-Type: application/zip", "Content-Disposition: attachment; filename*=UTF-8''r%C3%A9port%20one.zip", "Content-Transfer-Encoding: base64", "", Buffer.from("PK\u0003\u0004data").toString("base64"), "--x--"].join("\r\n"), "latin1"));
  check("mime: RFC 2231 file name", rfc2231.attachments[0].name === "réport one.zip" && rfc2231.attachments[0].bytes.subarray(0, 2).toString() === "PK");

  const qp = extractMessage(Buffer.from(["From: =?utf-8?B?UmVwb3J0ZXI=?= <r@x.test>", "Subject: =?utf-8?Q?Report_=C3=A9?=", "Content-Type: multipart/mixed; boundary=x", "", "--x", "Content-Type: text/xml", "Content-Transfer-Encoding: quoted-printable", "", "<feedback a=3D\"1\">=", "</feedback>", "--x--"].join("\r\n"), "latin1"));
  check("mime: encoded words, quoted-printable, and inline XML kept", qp.subject === "Report é" && qp.from === "r@x.test" && qp.attachments.length === 1 && qp.attachments[0].bytes.toString() === "<feedback a=\"1\"></feedback>", JSON.stringify(qp.attachments.map((a) => a.bytes.toString())));
  check("mime: plain text message has no attachments", extractMessage("From: a@b\r\nSubject: hi\r\n\r\nhello").attachments.length === 0);

  // === raw-source adapter ===
  const store = { k1: msgGoogle, k2: msgMicrosoft };
  const calls = { opens: 0, closes: 0, fetches: [] };
  const fake = createRawSource({
    type: "imap",
    idPrefix: "imap:box1:",
    isConfigured: () => true,
    open: async () => {
      calls.opens += 1;
      return {
        async *list({ since }) { calls.since = since; yield { key: "k1" }; yield { key: "k2", receivedAt: 1_758_600_000 }; },
        async fetchRaw(key) { calls.fetches.push(key); return store[key]; },
        async close() { calls.closes += 1; }
      };
    },
    test: async () => "fine"
  });
  const seen = [];
  let listedDate = null;
  for await (const m of fake.listMessages({ since: 1_758_000_000_000 })) {
    if (m.id.endsWith("k2")) listedDate = m.receivedAt;
    if (m.id.endsWith("k1")) {
      check("adapter: nothing is downloaded at list time", calls.fetches.length === 0 && m.subject === null);
      const atts = await fake.getAttachments(m.id);
      check("adapter: attachments on demand, message filled in from the headers", atts.length === 1 && atts[0].bytes.equals(gzGoogle) && m.subject === "Report Domain: example.com" && m.from === "noreply-dmarc-support@google.com" && m.receivedAt === "2025-09-22T10:00:00.000Z" && m.internetMessageId === "<g@reporter.test>");
      await fake.getMime(m.id);
      check("adapter: a second read of the same message reuses the download", calls.fetches.length === 1);
    }
    seen.push(m.id);
  }
  check("adapter: ids carry the prefix; one session for the whole listing", seen.join(",") === "imap:box1:k1,imap:box1:k2" && calls.opens === 1 && calls.closes === 1 && calls.since === 1_758_000_000);
  check("adapter: a date known at list time is set before any download", listedDate === new Date(1_758_600_000 * 1000).toISOString());
  const mime = await fake.getMime("imap:box1:k2");
  check("adapter: fetching outside a listing opens and closes its own session", mime.includes("microsoft") && calls.opens === 2 && calls.closes === 2);
  check("adapter: test passes through", (await fake.testConnection()).ok === true);
  const broken = createRawSource({ type: "pop3", idPrefix: "p:", isConfigured: () => true, open: async () => { throw new SourceError("nope", { fatal: true, stage: "login" }); }, test: async () => { throw new SourceError("bad password", { fatal: true, stage: "login" }); } });
  const brokenTest = await broken.testConnection();
  check("adapter: a failing test reports its stage", brokenTest.ok === false && brokenTest.stage === "login" && brokenTest.detail === "bad password");
  const notConfigured = createRawSource({ type: "pop3", idPrefix: "p:", isConfigured: () => false, missing: () => ["host"], open: async () => ({}), test: async () => "x" });
  check("adapter: unconfigured test says what is missing", (await notConfigured.testConnection()).stage === "config");

  // === POP3 against a mock server ===
  const popLog = [];
  const popMessages = [["uid-a", msgGoogle], ["uid-b", Buffer.from("From: x@y.test\r\nSubject: dots\r\n\r\n.leading dot line\r\nnormal\r\n", "latin1")]];
  const popServer = net.createServer((sock) => {
    let user = null;
    let buf = "";
    sock.write("+OK mock POP3 ready\r\n");
    sock.on("data", (d) => {
      buf += d.toString("latin1");
      let idx;
      while ((idx = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        popLog.push(line.replace(/^PASS .*/, "PASS ***"));
        const [cmd, arg] = line.split(" ");
        if (cmd === "USER") { user = arg; sock.write("+OK\r\n"); }
        else if (cmd === "PASS") { sock.write(user === "reports" && arg === "secret" ? "+OK logged in\r\n" : "-ERR invalid credentials\r\n"); }
        else if (cmd === "UIDL") { sock.write(`+OK\r\n${popMessages.map(([id], i) => `${i + 1} ${id}`).join("\r\n")}\r\n.\r\n`); }
        else if (cmd === "RETR") {
          const body = popMessages[Number(arg) - 1][1].toString("latin1").replace(/(^|\r\n)\./g, "$1..");
          sock.write(`+OK message follows\r\n${body}${body.endsWith("\r\n") ? "" : "\r\n"}.\r\n`);
        } else if (cmd === "QUIT") { sock.write("+OK bye\r\n"); sock.end(); }
        else sock.write("-ERR unknown\r\n");
      }
    });
    sock.on("error", () => {});
  });
  const popPort = await listen(popServer);
  const pop = createPop3Source({ host: "127.0.0.1", port: popPort, security: "none", username: "reports", password: "secret" }, { idPrefix: "pop3:bx:", timeoutMs: 5000 });
  const popTest = await pop.testConnection();
  check("pop3: connection test signs in and counts messages", popTest.ok && /holds 2 messages/.test(popTest.detail), JSON.stringify(popTest));
  const popSeen = [];
  let popAtt = null;
  let dots = null;
  for await (const m of pop.listMessages({})) {
    popSeen.push(m.id);
    if (m.id.endsWith("uid-a")) popAtt = await pop.getAttachments(m.id);
    if (m.id.endsWith("uid-b")) dots = await pop.getMime(m.id);
  }
  check("pop3: lists by UIDL, oldest first", popSeen.join(",") === "pop3:bx:uid-a,pop3:bx:uid-b");
  check("pop3: RETR returns the message intact", popAtt && popAtt.length === 1 && popAtt[0].bytes.equals(gzGoogle));
  check("pop3: dot-stuffed lines are restored", dots && dots.includes("\r\n.leading dot line\r\n") && !dots.includes(".."));
  check("pop3: never deletes, always quits", !popLog.some((l) => l.startsWith("DELE")) && popLog.filter((l) => l === "QUIT").length >= 2);
  const popBad = await createPop3Source({ host: "127.0.0.1", port: popPort, security: "none", username: "reports", password: "wrong" }, { timeoutMs: 5000 }).testConnection();
  check("pop3: wrong password is a login failure with advice", popBad.ok === false && popBad.stage === "login" && /app password/.test(popBad.detail), JSON.stringify(popBad));
  await closeServer(popServer);
  const popDown = await createPop3Source({ host: "127.0.0.1", port: popPort, security: "none", username: "u", password: "p" }, { timeoutMs: 3000 }).testConnection();
  check("pop3: unreachable host is a connection failure", popDown.ok === false && popDown.stage === "connection", JSON.stringify(popDown));

  // === IMAP through a fake client ===
  const imapState = { opened: [], searched: [], fetched: [], loggedOut: 0, options: null };
  class FakeImap {
    constructor(options) { imapState.options = options; this.options = options; }
    on() {}
    async connect() {
      if (this.options.auth.pass !== "secret") { const e = new Error("Command failed"); e.authenticationFailed = true; e.responseText = "[AUTHENTICATIONFAILED] Invalid credentials"; throw e; }
    }
    async mailboxOpen(name, opts) {
      imapState.opened.push([name, opts]);
      if (name === "Missing") { const e = new Error("no"); e.responseText = "Mailbox does not exist"; throw e; }
      return { uidValidity: 777n, exists: 2 };
    }
    async search(query, opts) { imapState.searched.push([query, opts]); return [12, 5]; }
    async fetchOne(uid, query, opts) {
      imapState.fetched.push([uid, query, opts]);
      return uid === "5" ? { source: msgGoogle, internalDate: new Date("2025-09-22T10:05:00Z") } : uid === "12" ? { source: msgMicrosoft, internalDate: new Date("2025-09-23T11:05:00Z") } : null;
    }
    async logout() { imapState.loggedOut += 1; }
  }
  const imap = createImapSource({ host: "mail.example.test", security: "tls", username: "reports@example.test", password: "secret", folder: "DMARC" }, { idPrefix: "imap:bx:", ImapClient: FakeImap });
  check("imap: defaults to port 993 with TLS and certificate checking", imapState.options === null && imap.config.port === 993 && imap.describe().security === "tls");
  const imapSeen = [];
  for await (const m of imap.listMessages({ since: Date.parse("2025-09-20T00:00:00Z") })) {
    await imap.getAttachments(m.id);
    imapSeen.push([m.id, m.receivedAt, m.subject]);
  }
  check("imap: connects with TLS, opens the folder read-only", imapState.options.secure === true && imapState.options.tls.rejectUnauthorized === true && imapState.opened[0][0] === "DMARC" && imapState.opened[0][1].readOnly === true);
  check("imap: searches by date with UIDs and yields them in order", imapState.searched[0][0].since instanceof Date && imapState.searched[0][1].uid === true && imapSeen.map((s) => s[0]).join(",") === "imap:bx:777:5,imap:bx:777:12");
  check("imap: fetches the raw source by UID; the server's date wins", imapState.fetched[0][0] === "5" && imapState.fetched[0][1].source === true && imapState.fetched[0][2].uid === true && imapSeen[0][1] === "2025-09-22T10:05:00.000Z" && imapSeen[1][2].startsWith("Report Domain"));
  check("imap: logs out when the listing ends", imapState.loggedOut === 1);
  const imapBadPass = await createImapSource({ host: "h", username: "u", password: "wrong" }, { ImapClient: FakeImap }).testConnection();
  check("imap: rejected sign-in is a login failure", imapBadPass.ok === false && imapBadPass.stage === "login" && /rejected the sign-in/.test(imapBadPass.detail));
  const imapBadFolder = await createImapSource({ host: "h", username: "u", password: "secret", folder: "Missing" }, { ImapClient: FakeImap }).testConnection();
  check("imap: missing folder is a folder failure", imapBadFolder.ok === false && imapBadFolder.stage === "folder" && /Missing/.test(imapBadFolder.detail));
  const imapOk = await imap.testConnection();
  check("imap: test reports the folder size", imapOk.ok && /holds 2 messages/.test(imapOk.detail));
  await createImapSource({ host: "h", security: "starttls", username: "u", password: "secret", tlsVerify: false }, { ImapClient: FakeImap }).testConnection();
  check("imap: STARTTLS uses port 143, upgrades, and honours the certificate switch", imapState.options.secure === false && imapState.options.doSTARTTLS === true && imapState.options.port === 143 && imapState.options.tls.rejectUnauthorized === false);
  await createImapSource({ host: "h", security: "none", username: "u", password: "secret" }, { ImapClient: FakeImap }).testConnection();
  check("imap: 'none' forbids the STARTTLS upgrade", imapState.options.secure === false && imapState.options.doSTARTTLS === false);

  // === Gmail against a mock server ===
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const saKey = { type: "service_account", client_email: "dmarc-reader@proj.iam.gserviceaccount.com", private_key_id: "kid1", private_key: privateKey.export({ type: "pkcs8", format: "pem" }) };
  const gState = { tokenRequests: 0, queries: [], delegated: true, lastClaims: null };
  const gmailServer = http.createServer((req, res) => {
    const url = new URL(req.url, "http://mock");
    const send = (status, body) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(body)); };
    if (req.method === "POST" && url.pathname === "/token") {
      let body = "";
      req.on("data", (c) => { body += c; });
      req.on("end", () => {
        gState.tokenRequests += 1;
        const form = new URLSearchParams(body);
        const [h, c, sig] = String(form.get("assertion") || "").split(".");
        const ok = form.get("grant_type") === "urn:ietf:params:oauth:grant-type:jwt-bearer" && crypto.verify("sha256", Buffer.from(`${h}.${c}`), publicKey, Buffer.from(sig || "", "base64url"));
        gState.lastClaims = ok ? JSON.parse(Buffer.from(c, "base64url").toString()) : null;
        if (!ok) return send(400, { error: "invalid_grant", error_description: "Invalid JWT Signature." });
        if (!gState.delegated) return send(401, { error: "unauthorized_client", error_description: "Client is unauthorized to retrieve access tokens using this method." });
        send(200, { access_token: "g-token", expires_in: 3599, token_type: "Bearer" });
      });
      return;
    }
    if (req.headers.authorization !== "Bearer g-token") return send(401, { error: { message: "Invalid Credentials", status: "UNAUTHENTICATED" } });
    const m = url.pathname.match(/^\/gmail\/v1\/users\/([^/]+)\/(.*)$/);
    if (!m || decodeURIComponent(m[1]) !== "dmarc@example.com") return send(404, { error: { message: "Not Found" } });
    if (m[2] === "profile") return send(200, { emailAddress: "dmarc@example.com", messagesTotal: 42 });
    if (m[2] === "messages") {
      gState.queries.push(Object.fromEntries(url.searchParams.entries()));
      if (!url.searchParams.get("pageToken")) return send(200, { messages: [{ id: "g2" }], nextPageToken: "page2" });
      return send(200, { messages: [{ id: "g1" }] });
    }
    if (m[2] === "messages/g1") return send(200, { id: "g1", internalDate: String(Date.parse("2025-09-22T10:06:00Z")), raw: msgGoogle.toString("base64url") });
    if (m[2] === "messages/g2") return send(200, { id: "g2", internalDate: String(Date.parse("2025-09-23T11:06:00Z")), raw: msgMicrosoft.toString("base64url") });
    send(404, { error: { message: "Requested entity was not found." } });
  });
  const gPort = await listen(gmailServer);
  const gBase = `http://127.0.0.1:${gPort}`;
  const gmail = createGmailSource({ serviceAccountKey: JSON.stringify({ ...saKey, token_uri: `${gBase}/token` }), mailbox: "dmarc@example.com", folder: "DMARC Reports", apiBase: gBase }, { idPrefix: "gws:bx:" });
  const gTest = await gmail.testConnection();
  check("gmail: test exchanges a signed JWT and reads the profile", gTest.ok && /holds 42 messages/.test(gTest.detail) && /dmarc-reader@proj/.test(gTest.detail), JSON.stringify(gTest));
  check("gmail: the assertion impersonates the mailbox with the read-only scope", gState.lastClaims && gState.lastClaims.iss === saKey.client_email && gState.lastClaims.sub === "dmarc@example.com" && gState.lastClaims.scope === SCOPE && gState.lastClaims.aud === `${gBase}/token` && gState.lastClaims.exp - gState.lastClaims.iat === 3600);
  const gSeen = [];
  for await (const m of gmail.listMessages({ since: 1_758_000_000_000 })) {
    const atts = await gmail.getAttachments(m.id);
    gSeen.push([m.id, m.receivedAt, atts.length]);
  }
  check("gmail: pages through the listing", gSeen.map((s) => s[0]).sort().join(",") === "gws:bx:g1,gws:bx:g2" && gState.queries.length === 2 && gState.queries[1].pageToken === "page2");
  check("gmail: query carries the date and the label", gState.queries[0].q === "after:1758000000 label:DMARC-Reports", gState.queries[0].q);
  check("gmail: raw messages decode and internalDate is used", gSeen.every((s) => s[2] === 1) && gSeen.find((s) => s[0].endsWith("g1"))[1] === "2025-09-22T10:06:00.000Z");
  check("gmail: the token is reused across calls", gState.tokenRequests === 1);
  gState.delegated = false;
  const gDenied = await createGmailSource({ serviceAccountKey: { ...saKey, token_uri: `${gBase}/token` }, mailbox: "dmarc@example.com", apiBase: gBase }).testConnection();
  check("gmail: missing delegation explains where to grant it", gDenied.ok === false && gDenied.stage === "login" && /Domain-wide delegation/.test(gDenied.detail) && gDenied.detail.includes(SCOPE));
  await closeServer(gmailServer);
  const badKey = (() => { try { parseServiceAccount("{\"type\":\"authorized_user\"}"); return null; } catch (e) { return e; } })();
  check("gmail: a key that is not a service account is refused", badKey && /client_email or private_key/.test(badKey.message));
  check("gmail: non-JSON key is refused", (() => { try { parseServiceAccount("hello"); return false; } catch (e) { return /not valid JSON/.test(e.message); } })());

  // === S3 (Amazon SES) against a mock server ===
  const vectors = { region: "us-east-1", accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", now: new Date("2013-05-24T00:00:00Z") };
  check("s3: SigV4 matches AWS's GET Object example", signV4({ ...vectors, url: "https://examplebucket.s3.amazonaws.com/test.txt", headers: { Range: "bytes=0-9" } }).signature === "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
  check("s3: SigV4 matches AWS's List Objects example", signV4({ ...vectors, url: "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J" }).signature === "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7");

  const s3State = { requests: [], deny: false };
  const objects = {
    "inbound/AMAZON_SES_SETUP_NOTIFICATION": { body: Buffer.from("setup"), modified: "2025-09-01T00:00:00.000Z" },
    "inbound/old message": { body: msgGoogle, modified: "2025-08-01T00:00:00.000Z" },
    "inbound/abc123": { body: msgGoogle, modified: "2025-09-22T10:07:00.000Z" },
    "inbound/def456": { body: msgMicrosoft, modified: "2025-09-23T11:07:00.000Z" }
  };
  const s3Server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://mock");
    s3State.requests.push({ path: url.pathname, query: Object.fromEntries(url.searchParams.entries()), auth: req.headers.authorization || "", date: req.headers["x-amz-date"], sha: req.headers["x-amz-content-sha256"] });
    const xmlOut = (status, body) => { res.writeHead(status, { "Content-Type": "application/xml" }); res.end(body); };
    if (s3State.deny) return xmlOut(403, "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>");
    if (!url.pathname.startsWith("/ses-bucket/")) return xmlOut(404, "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>");
    const key = decodeURIComponent(url.pathname.slice("/ses-bucket/".length));
    if (!key) {
      const keys = Object.keys(objects).filter((k) => k.startsWith(url.searchParams.get("prefix") || ""));
      const second = url.searchParams.get("continuation-token") === "next";
      const page = second ? keys.slice(2) : keys.slice(0, 2);
      const truncated = !second && keys.length > 2;
      return xmlOut(200, `<?xml version="1.0"?><ListBucketResult><Name>ses-bucket</Name><KeyCount>${page.length}</KeyCount><IsTruncated>${truncated}</IsTruncated>${truncated ? "<NextContinuationToken>next</NextContinuationToken>" : ""}${page.map((k) => `<Contents><Key>${k}</Key><LastModified>${objects[k].modified}</LastModified><Size>${objects[k].body.length}</Size></Contents>`).join("")}</ListBucketResult>`);
    }
    if (!objects[key]) return xmlOut(404, "<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>");
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    res.end(objects[key].body);
  });
  const s3Port = await listen(s3Server);
  const s3 = createS3Source({ region: "eu-west-1", bucket: "ses-bucket", prefix: "inbound/", accessKeyId: "AKIATEST", secretAccessKey: "secret", endpoint: `http://127.0.0.1:${s3Port}` }, { idPrefix: "ses:bx:" });
  const s3Test = await s3.testConnection();
  check("s3: test lists the prefix", s3Test.ok && /s3:\/\/ses-bucket\/inbound\//.test(s3Test.detail), JSON.stringify(s3Test));
  const s3Seen = [];
  for await (const m of s3.listMessages({ since: Date.parse("2025-09-01T00:00:00Z") })) {
    const atts = await s3.getAttachments(m.id);
    s3Seen.push([m.id, m.receivedAt, atts.length, m.subject]);
  }
  check("s3: follows continuation, skips the setup file and objects older than the cursor", s3Seen.map((s) => s[0]).join(",") === "ses:bx:inbound/abc123,ses:bx:inbound/def456", JSON.stringify(s3Seen.map((s) => s[0])));
  check("s3: LastModified is the received time and the object parses as a message", s3Seen[0][1] === "2025-09-22T10:07:00.000Z" && s3Seen[0][2] === 1 && s3Seen[1][3].startsWith("Report Domain"));
  check("s3: every request is signed for the configured region", s3State.requests.every((r) => /^AWS4-HMAC-SHA256 Credential=AKIATEST\/\d{8}\/eu-west-1\/s3\/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/.test(r.auth) && r.date && r.sha));
  check("s3: listing uses ListObjectsV2 with the prefix", s3State.requests.some((r) => r.query["list-type"] === "2" && r.query.prefix === "inbound/" && r.query["continuation-token"] === "next"));
  const spaced = await s3.getMime("ses:bx:inbound/old message");
  check("s3: keys with spaces are encoded", spaced.includes("Report Domain") && s3State.requests.some((r) => r.path === "/ses-bucket/inbound/old%20message"));
  s3State.deny = true;
  const s3Denied = await s3.testConnection();
  check("s3: AccessDenied names the permissions needed", s3Denied.ok === false && s3Denied.stage === "login" && /s3:ListBucket/.test(s3Denied.detail) && /s3:GetObject/.test(s3Denied.detail));
  s3State.deny = false;

  // === mailbox store: types ===
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-src-"));
  const boxes = createMailboxStore({ dataDir, env: {}, sourceOptions: { imap: { ImapClient: FakeImap } } });
  const bad = (fields) => { try { boxes.add(fields); return null; } catch (e) { return e; } };
  check("store: unknown type refused", bad({ type: "carrier-pigeon" })?.status === 400);
  check("store: imap needs host, username, password", bad({ type: "imap", username: "u", password: "p" })?.status === 400 && bad({ type: "imap", host: "h", password: "p" })?.status === 400 && bad({ type: "imap", host: "h", username: "u" })?.status === 400);
  check("store: imap rejects a bad port and security", bad({ type: "imap", host: "h", username: "u", password: "p", port: "99999" })?.status === 400 && bad({ type: "imap", host: "h", username: "u", password: "p", security: "ssl3" })?.status === 400);
  const imapBox = boxes.add({ type: "imap", name: "Fastmail", host: "IMAP.Example.Test", username: "reports@example.test", password: "secret", folder: "DMARC" });
  check("store: imap entry gets defaults and hides the password", imapBox.type === "imap" && imapBox.typeLabel === "IMAP" && imapBox.host === "imap.example.test" && imapBox.port === 993 && imapBox.security === "tls" && imapBox.mailbox === "reports@example.test" && imapBox.folder === "DMARC" && imapBox.authMethod === "password" && imapBox.hasSecret === true && !("password" in imapBox));
  check("store: the file keeps the password and the type", (() => { const row = JSON.parse(fs.readFileSync(boxes.file, "utf8"))[0]; return row.password === "secret" && row.type === "imap"; })());
  check("store: same server, user and folder is a duplicate; another folder is not", bad({ type: "imap", host: "imap.example.test", username: "reports@example.test", password: "x", folder: "DMARC" })?.status === 409 && bad({ type: "imap", host: "imap.example.test", username: "reports@example.test", password: "x", folder: "Other" }) === null);
  const kept = boxes.update(imapBox.id, { name: "Fastmail 2", password: "" });
  check("store: update keeps the password when blank", kept.name === "Fastmail 2" && boxes.get(imapBox.id).password === "secret");
  check("store: a mailbox's type cannot be changed", (() => { try { boxes.update(imapBox.id, { type: "pop3" }); return false; } catch (e) { return e.status === 400; } })());
  const popBox = boxes.add({ type: "pop3", host: "pop.example.test", username: "reports", password: "p", security: "starttls", mailbox: "reports@example.test" });
  check("store: pop3 defaults to port 110 with STARTTLS and has no folder", popBox.port === 110 && popBox.folder === "" && popBox.typeLabel === "POP3");
  check("store: gws needs a real service account key and an address", bad({ type: "gws", mailbox: "dmarc@example.com", serviceAccountKey: "{}" })?.status === 400 && bad({ type: "gws", mailbox: "nope", serviceAccountKey: JSON.stringify(saKey) })?.status === 400);
  const gwsBox = boxes.add({ type: "gws", mailbox: "DMARC@example.com", serviceAccountKey: JSON.stringify(saKey), folder: "DMARC" });
  check("store: gws shows the service account address, never the key", gwsBox.serviceAccount === saKey.client_email && gwsBox.authMethod === "service account" && !JSON.stringify(gwsBox).includes("PRIVATE KEY") && gwsBox.mailbox === "dmarc@example.com");
  check("store: ses needs region, bucket and both keys", bad({ type: "ses", bucket: "b", accessKeyId: "a", secretAccessKey: "s" })?.status === 400 && bad({ type: "ses", region: "us-east-1", bucket: "s3://b", accessKeyId: "a", secretAccessKey: "s" })?.status === 400 && bad({ type: "ses", region: "us-east-1", bucket: "b", accessKeyId: "a" })?.status === 400);
  const sesBox = boxes.add({ type: "ses", region: "US-EAST-1", bucket: "ses-bucket", prefix: "/inbound/", accessKeyId: "AKIATEST", secretAccessKey: "topsecret" });
  check("store: ses entry is normalised, labelled, and hides the secret key", sesBox.region === "us-east-1" && sesBox.prefix === "inbound/" && sesBox.mailbox === "s3://ses-bucket/inbound/" && sesBox.authMethod === "access key" && sesBox.accessKeyId === "AKIATEST" && !JSON.stringify(sesBox).includes("topsecret"));
  check("store: every listed entry is free of credentials", !/secret|PRIVATE KEY|topsecret/.test(JSON.stringify(boxes.list().map(({ name, ...rest }) => rest)).replace(/hasSecret/g, "")));
  check("store: clients are built per type", boxes.clientFor(imapBox.id).type === "imap" && boxes.clientFor(popBox.id).type === "pop3" && boxes.clientFor(gwsBox.id).type === "gws" && boxes.clientFor(sesBox.id).type === "ses");
  check("store: graph entries still work and are labelled", (() => { const g = boxes.add({ tenantId: "t", clientId: "c", clientSecret: "s", mailbox: "g@example.test" }); return g.type === "graph" && g.typeLabel === "Microsoft 365" && typeof boxes.clientFor(g.id).getToken === "function"; })());
  check("store: all five types are declared", Object.keys(TYPES).join(",") === "graph,gws,ses,imap,pop3");

  // === sync end to end through an IMAP mailbox ===
  const db = openDatabase({ file: ":memory:" });
  const onlyImap = createMailboxStore({ dataDir: fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-src2-")), env: {}, sourceOptions: { imap: { ImapClient: FakeImap } } });
  const syncBox = onlyImap.add({ type: "imap", host: "mail.example.test", username: "reports@example.test", password: "secret", folder: "DMARC" });
  imapState.fetched.length = 0;
  const quiet = { warn() {}, error() {}, log() {} };
  const noDns = async () => { const e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e; };
  const runToEnd = async (engine) => { const { job: j } = engine.runSync({ trigger: "manual" }); await j.promise; if (j.ptrPromise) await j.ptrPromise; return j; };
  const sync = createSync({ db, mailboxes: onlyImap, backfillDays: 30, resolver: noDns, logger: quiet });
  const job = await runToEnd(sync);
  check("sync: reports are ingested from an IMAP mailbox", job.added === 2 && job.errors === 0 && db.stats().reports.reports === 2, JSON.stringify({ added: job.added, errors: job.errors, lastError: job.lastError }));
  const stored = db.db.prepare("SELECT graph_id, mailbox_id, subject, from_addr, status FROM messages ORDER BY received_at").all();
  check("sync: messages are recorded with prefixed ids, sender and subject", stored.length === 2 && stored[0].graph_id === `imap:${syncBox.id}:777:5` && stored[0].mailbox_id === syncBox.id && stored[0].from_addr === "noreply-dmarc-support@google.com" && stored.every((m) => m.status === "ingested"), JSON.stringify(stored));
  const again = await runToEnd(sync);
  check("sync: a second run downloads nothing it has already seen", again.added === 0 && again.skipped === 2 && imapState.fetched.length === 2);
  const badStore = createMailboxStore({ dataDir: fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-src3-")), env: {}, sourceOptions: { imap: { ImapClient: FakeImap } } });
  badStore.add({ type: "imap", host: "mail.example.test", username: "reports@example.test", password: "wrong" });
  const failed = await runToEnd(createSync({ db, mailboxes: badStore, backfillDays: 30, resolver: noDns, logger: quiet }));
  check("sync: a rejected sign-in fails that mailbox with the reason", failed.mailboxes[0].status === "failed" && /rejected the sign-in/.test(failed.mailboxes[0].error), JSON.stringify(failed.mailboxes[0]));

  await closeServer(s3Server);
  db.close();
  process.exitCode = report() ? 0 : 1;
})().catch((e) => { console.error(e); process.exit(1); });
