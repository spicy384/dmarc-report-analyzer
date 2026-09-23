/**
 * A tiny stand-in for the Microsoft identity platform and Graph, just enough
 * for the sync tests: token endpoint, folder lookup, paged message listing and
 * attachment download. Behaviour is scripted through `state` so tests can inject
 * throttling, transient failures and permission errors.
 */
const http = require("http");

function createMockGraph({ mailbox = "dmarc@example.com", secret = "s3cret", messages = [], mailboxes = {} } = {}) {
  const state = {
    messages,            // [{ id, subject, receivedDateTime, from, attachments: [{ name, contentType, bytes }] }]
    mailboxes: { [mailbox]: messages, ...mailboxes }, // extra UPNs -> their own message lists
    requests: [],        // every request seen: { method, path }
    throttleOnce: false, // next message listing gets a 429 first
    failAttachmentsOnce: new Set(), // message ids whose attachment fetch 500s once
    listStatus: null     // force a status (e.g. 403) on message listing
  };

  function json(res, status, body) {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  }

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://mock");
    state.requests.push({ method: req.method, path: url.pathname + url.search });
    const auth = req.headers.authorization;

    // --- token --------------------------------------------------------------
    if (req.method === "POST" && /\/oauth2\/v2\.0\/token$/.test(url.pathname)) {
      let body = "";
      req.on("data", (c) => { body += c; });
      req.on("end", () => {
        const form = new URLSearchParams(body);
        if (form.get("client_secret") !== secret) {
          return json(res, 401, { error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret provided." });
        }
        json(res, 200, { token_type: "Bearer", expires_in: 3599, access_token: "mock-token" });
      });
      return;
    }

    if (auth !== "Bearer mock-token") {
      return json(res, 401, { error: { code: "InvalidAuthenticationToken", message: "Access token is empty." } });
    }

    const userMatch = url.pathname.match(/^\/v1\.0\/users\/([^/]+)(.*)$/);
    const upn = userMatch ? decodeURIComponent(userMatch[1]) : null;
    if (!upn || !Object.prototype.hasOwnProperty.call(state.mailboxes, upn)) {
      return json(res, 404, { error: { code: "ErrorInvalidUser", message: `The requested user '${upn}' is invalid.` } });
    }
    const boxMessages = state.mailboxes[upn];
    const rest = userMatch[2];

    // --- folders ------------------------------------------------------------
    if (rest === "/mailFolders/inbox" && req.method === "GET") {
      return json(res, 200, { id: "inbox-id", displayName: "Inbox", totalItemCount: boxMessages.length });
    }
    if (rest === "/mailFolders" && req.method === "GET") {
      const filter = url.searchParams.get("$filter") || "";
      const m = filter.match(/displayName eq '(.*)'/);
      const name = m ? m[1].replace(/''/g, "'") : "";
      const value = name === "DMARC Reports" ? [{ id: "folder-dmarc", displayName: "DMARC Reports" }] : [];
      return json(res, 200, { value });
    }

    // --- messages -----------------------------------------------------------
    const listMatch = rest.match(/^\/mailFolders\/([^/]+)\/messages$/);
    if (listMatch && req.method === "GET") {
      if (state.listStatus) {
        const status = state.listStatus;
        state.listStatus = null;
        return json(res, status, { error: { code: status === 403 ? "ErrorAccessDenied" : "Error", message: "Access is denied. Check credentials and try again." } });
      }
      if (state.throttleOnce) {
        state.throttleOnce = false;
        res.writeHead(429, { "Content-Type": "application/json", "Retry-After": "0" });
        return res.end(JSON.stringify({ error: { code: "TooManyRequests", message: "slow down" } }));
      }
      const page = Number(url.searchParams.get("page") || 1);
      const top = Number(url.searchParams.get("$top") || 100);
      const pageSize = Math.min(top, 4);
      const slice = boxMessages.slice((page - 1) * pageSize, page * pageSize);
      const body = {
        value: slice.map((m) => ({
          id: m.id,
          internetMessageId: `<${m.id}@mock>`,
          subject: m.subject,
          receivedDateTime: m.receivedDateTime,
          hasAttachments: m.attachments.length > 0,
          from: { emailAddress: { address: m.from } }
        }))
      };
      if (page * pageSize < boxMessages.length) {
        const next = new URL(url.toString());
        next.searchParams.set("page", String(page + 1));
        body["@odata.nextLink"] = `http://127.0.0.1:${server.address().port}${next.pathname}${next.search}`;
      }
      return json(res, 200, body);
    }

    const attMatch = rest.match(/^\/messages\/([^/]+)\/attachments$/);
    if (attMatch && req.method === "GET") {
      const id = decodeURIComponent(attMatch[1]);
      if (state.failAttachmentsOnce.has(id)) {
        state.failAttachmentsOnce.delete(id);
        return json(res, 500, { error: { code: "InternalServerError", message: "try again" } });
      }
      const message = boxMessages.find((m) => m.id === id);
      if (!message) {
        return json(res, 404, { error: { code: "ErrorItemNotFound", message: "not found" } });
      }
      return json(res, 200, {
        value: message.attachments.map((a, i) => ({
          "@odata.type": a.type || "#microsoft.graph.fileAttachment",
          id: `${id}-att-${i}`,
          name: a.name,
          contentType: a.contentType || "application/octet-stream",
          size: a.bytes ? a.bytes.length : 0,
          contentBytes: a.bytes ? Buffer.from(a.bytes).toString("base64") : undefined
        }))
      });
    }

    json(res, 404, { error: { code: "ResourceNotFound", message: `no route for ${req.method} ${rest}` } });
  });

  function start() {
    return new Promise((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const port = server.address().port;
        resolve({
          port,
          loginBase: `http://127.0.0.1:${port}`,
          graphBase: `http://127.0.0.1:${port}/v1.0`
        });
      });
    });
  }

  function stop() {
    return new Promise((resolve) => server.close(resolve));
  }

  return { state, server, start, stop, mailbox, secret };
}

module.exports = { createMockGraph };
