/**
 * Authentication end-to-end tests: boots the real server against a throwaway
 * data directory and exercises setup, login, TOTP, recovery codes, lockout,
 * CSRF and route gating.
 */
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const authLib = require("../auth");
const { createChecker } = require("./helpers/assert");

const PROJECT = path.join(__dirname, "..");
const APP_PORT = Number(process.env.TEST_AUTH_PORT) || 3986;
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-auth-"));

const { check, report } = createChecker("Auth: sessions, TOTP, lockout, gating");

let cookie = null;
let csrf = null;

async function req(pathname, { method = "GET", body, useCsrf = true, cookieOverride } = {}) {
  const headers = { "Content-Type": "application/json" };
  const jar = cookieOverride !== undefined ? cookieOverride : cookie;
  if (jar) headers.Cookie = jar;
  if (useCsrf && csrf) headers["X-CSRF-Token"] = csrf;

  const res = await fetch(`http://127.0.0.1:${APP_PORT}${pathname}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });

  const setCookie = res.headers.get("set-cookie");
  if (setCookie) {
    const m = setCookie.match(/dmarc_session=([^;]*)/);
    if (m) cookie = m[1] ? `dmarc_session=${m[1]}` : null;
  }

  const json = await res.json().catch(() => ({}));
  return { status: res.status, body: json };
}

async function waitForServer(tries = 60) {
  for (let i = 0; i < tries; i += 1) {
    try {
      const r = await fetch(`http://127.0.0.1:${APP_PORT}/api/auth/me`);
      if (r.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("auth test server did not start");
}

const PROTECTED = [
  ["GET", "/api/status"], ["GET", "/api/summary"], ["GET", "/api/ips"],
  ["GET", "/api/reports"], ["GET", "/api/domains"], ["GET", "/api/reporters"],
  ["POST", "/api/sync"], ["POST", "/api/mailboxes"]
];

(async () => {
  const app = spawn("node", ["server.js"], {
    cwd: PROJECT,
    env: { ...process.env, PORT: String(APP_PORT), DATA_DIR },
    stdio: ["ignore", "pipe", "pipe"]
  });
  app.stderr.on("data", (d) => console.error("[app stderr]", d.toString().trim()));

  try {
    await waitForServer();

    // === before setup ===
    const me0 = await req("/api/auth/me");
    check("reports setup required with no users", me0.body.setupRequired === true && me0.body.authenticated === false);

    for (const [method, p] of PROTECTED) {
      const r = await req(p, { method, body: method === "GET" ? undefined : {} });
      check(`${method} ${p} blocked before setup`, r.status === 409, String(r.status));
    }

    // === setup validation ===
    check("setup rejects short password", (await req("/api/auth/setup", { method: "POST", body: { username: "admin", password: "short" } })).status === 400);
    check("setup rejects bad username", (await req("/api/auth/setup", { method: "POST", body: { username: "a b!", password: "correct-horse-battery" } })).status === 400);

    // === setup ===
    const setup = await req("/api/auth/setup", { method: "POST", body: { username: "admin", password: "correct-horse-battery" } });
    check("setup succeeds", setup.status === 200 && setup.body.ok === true, JSON.stringify(setup.body));
    check("setup returns admin role", setup.body.user?.role === "admin");
    check("setup issues a session cookie", Boolean(cookie));
    check("setup returns a csrf token", Boolean(setup.body.csrfToken));
    csrf = setup.body.csrfToken;

    check("setup cannot run twice", (await req("/api/auth/setup", { method: "POST", body: { username: "x2", password: "correct-horse-battery" } })).status === 409);

    // === authenticated access ===
    for (const [method, p] of PROTECTED) {
      const r = await req(p, { method, body: method === "GET" ? undefined : {} });
      check(`${method} ${p} reachable when signed in`, r.status !== 401 && r.status !== 409, String(r.status));
    }

    // === CSRF ===
    const noCsrf = await req("/api/sync", { method: "POST", body: {}, useCsrf: false });
    check("state change without CSRF token is rejected", noCsrf.status === 403, String(noCsrf.status));
    const badCsrf = (await (async () => { const saved = csrf; csrf = "wrong-token"; const r = await req("/api/sync", { method: "POST", body: {} }); csrf = saved; return r; })());
    check("state change with wrong CSRF token is rejected", badCsrf.status === 403, String(badCsrf.status));
    check("GET does not require CSRF", (await req("/api/reports", { useCsrf: false })).status === 200);

    // === session cookie is required ===
    const noCookie = await req("/api/reports", { cookieOverride: null });
    check("request without session cookie is rejected", noCookie.status === 401, String(noCookie.status));
    const badCookie = await req("/api/reports", { cookieOverride: "dmarc_session=deadbeef" });
    check("request with invalid session cookie is rejected", badCookie.status === 401, String(badCookie.status));

    // === MFA enrolment ===
    const mfa = await req("/api/auth/mfa/setup", { method: "POST", body: {} });
    check("mfa setup returns a secret", typeof mfa.body.secret === "string" && mfa.body.secret.length >= 16);
    check("mfa setup returns an otpauth uri", String(mfa.body.uri || "").startsWith("otpauth://totp/"));
    check("mfa setup returns a QR data url", String(mfa.body.qrDataUrl || "").startsWith("data:image/png;base64,"));

    check("wrong code does not enrol", (await req("/api/auth/mfa/confirm", { method: "POST", body: { code: "000000" } })).status === 400);

    const confirm = await req("/api/auth/mfa/confirm", { method: "POST", body: { code: authLib.totp(mfa.body.secret) } });
    check("correct code enrols mfa", confirm.status === 200, JSON.stringify(confirm.body));
    check("enrolment returns 10 recovery codes", (confirm.body.recoveryCodes || []).length === 10);
    const recoveryCodes = confirm.body.recoveryCodes;

    const meAfter = await req("/api/auth/me");
    check("me reports mfa enrolled", meAfter.body.user?.mfaEnrolled === true);

    // === logout ===
    check("logout succeeds", (await req("/api/auth/logout", { method: "POST", body: {} })).status === 200);
    check("session invalid after logout", (await req("/api/auth/me")).body.authenticated === false);
    csrf = null;

    // === login now demands MFA ===
    const login = await req("/api/auth/login", { method: "POST", body: { username: "admin", password: "correct-horse-battery" } });
    check("login requires mfa", login.body.mfaRequired === true && Boolean(login.body.pendingToken));
    check("password alone grants no session", (await req("/api/auth/me")).body.authenticated === false);

    check("wrong mfa code rejected", (await req("/api/auth/login/mfa", { method: "POST", body: { pendingToken: login.body.pendingToken, code: "000000" } })).status === 401);

    const secret = JSON.parse(fs.readFileSync(path.join(DATA_DIR, "users.json"), "utf8"))[0].totpSecret;

    // Enrolment consumed the current window's counter, so that exact code can no longer
    // be used to sign in. Use the next window's code, which the drift allowance accepts.
    const enrolReplay = await req("/api/auth/login/mfa", { method: "POST", body: { pendingToken: login.body.pendingToken, code: authLib.totp(secret) } });
    check("the code used to enrol cannot then be used to sign in", enrolReplay.status === 401 && /already been used/i.test(enrolReplay.body.error || ""), JSON.stringify(enrolReplay.body));

    const nextCode = authLib.totp(secret, { time: Date.now() + 30000 });
    const login1b = await req("/api/auth/login", { method: "POST", body: { username: "admin", password: "correct-horse-battery" } });
    const mfaLogin = await req("/api/auth/login/mfa", { method: "POST", body: { pendingToken: login1b.body.pendingToken, code: nextCode } });
    check("correct mfa code signs in", mfaLogin.status === 200 && Boolean(mfaLogin.body.csrfToken), JSON.stringify(mfaLogin.body));
    csrf = mfaLogin.body.csrfToken;
    check("session works after mfa login", (await req("/api/auth/me")).body.authenticated === true);

    // === TOTP replay is refused ===
    await req("/api/auth/logout", { method: "POST", body: {} });
    csrf = null;
    const login2 = await req("/api/auth/login", { method: "POST", body: { username: "admin", password: "correct-horse-battery" } });
    const replay = await req("/api/auth/login/mfa", { method: "POST", body: { pendingToken: login2.body.pendingToken, code: nextCode } });
    check("reusing an already-used TOTP code is refused", replay.status === 401 && /already been used/i.test(replay.body.error || ""), JSON.stringify(replay.body));

    // === recovery code ===
    const login3 = await req("/api/auth/login", { method: "POST", body: { username: "admin", password: "correct-horse-battery" } });
    const rec = await req("/api/auth/login/recovery", { method: "POST", body: { pendingToken: login3.body.pendingToken, code: recoveryCodes[0] } });
    check("recovery code signs in", rec.status === 200, JSON.stringify(rec.body));
    check("recovery code is consumed", rec.body.recoveryCodesRemaining === 9);
    csrf = rec.body.csrfToken;

    const login4 = await req("/api/auth/login", { method: "POST", body: { username: "admin", password: "correct-horse-battery" } });
    const reuse = await req("/api/auth/login/recovery", { method: "POST", body: { pendingToken: login4.body.pendingToken, code: recoveryCodes[0] } });
    check("a used recovery code cannot be reused", reuse.status === 401, String(reuse.status));

    // sign back in for the remaining tests
    const login5 = await req("/api/auth/login", { method: "POST", body: { username: "admin", password: "correct-horse-battery" } });
    const back = await req("/api/auth/login/recovery", { method: "POST", body: { pendingToken: login5.body.pendingToken, code: recoveryCodes[1] } });
    csrf = back.body.csrfToken;

    // === user management ===
    const add = await req("/api/users", { method: "POST", body: { username: "operator", password: "another-long-password", role: "user" } });
    check("admin can add a user", add.status === 200, JSON.stringify(add.body));
    check("duplicate username refused", (await req("/api/users", { method: "POST", body: { username: "operator", password: "another-long-password" } })).status === 409);
    check("weak password refused", (await req("/api/users", { method: "POST", body: { username: "weak", password: "short" } })).status === 400);
    check("user list shows both", ((await req("/api/users")).body.users || []).length === 2);
    check("password hashes never leave the server", !JSON.stringify((await req("/api/users")).body).includes("scrypt$"));

    const adminId = (await req("/api/auth/me")).body.user.id;
    check("cannot delete yourself", (await req(`/api/users/${adminId}`, { method: "DELETE" })).status === 400);

    // === non-admin restrictions ===
    const adminCookie = cookie;
    const adminCsrf = csrf;
    cookie = null; csrf = null;
    const opLogin = await req("/api/auth/login", { method: "POST", body: { username: "operator", password: "another-long-password" } });
    csrf = opLogin.body.csrfToken;
    check("new user signs in without mfa until enrolled", opLogin.status === 200 && opLogin.body.mfaRequired === false);
    check("non-admin cannot list users", (await req("/api/users")).status === 403);
    check("non-admin cannot add users", (await req("/api/users", { method: "POST", body: { username: "x9", password: "another-long-password" } })).status === 403);
    check("non-admin can still use the app", (await req("/api/reports")).status === 200);
    check("non-admin cannot add a mailbox", (await req("/api/mailboxes", { method: "POST", body: {} })).status === 403);
    check("non-admin cannot change roles", (await req(`/api/users/${adminId}/role`, { method: "POST", body: { role: "viewer" } })).status === 403);

    cookie = adminCookie; csrf = adminCsrf;

    // === viewer role ===
    const addViewer = await req("/api/users", { method: "POST", body: { username: "watcher", password: "watcher-long-password", role: "viewer" } });
    check("admin can add a viewer", addViewer.status === 200 && addViewer.body.user.role === "viewer", JSON.stringify(addViewer.body));
    check("unknown role falls back to user", (await req("/api/users", { method: "POST", body: { username: "odd", password: "another-long-password", role: "superuser" } })).body.user.role === "user");
    const viewerId = addViewer.body.user.id;
    const operatorId = ((await req("/api/users")).body.users.find((u) => u.username === "operator") || {}).id;

    check("admin cannot change their own role", (await req(`/api/users/${adminId}/role`, { method: "POST", body: { role: "user" } })).status === 400);
    check("cannot demote the last administrator", (await req(`/api/users/${adminId}/role`, { method: "POST", body: { role: "viewer" } })).status === 400);
    check("role must be valid", (await req(`/api/users/${operatorId}/role`, { method: "POST", body: { role: "root" } })).status === 400);
    const promote = await req(`/api/users/${operatorId}/role`, { method: "POST", body: { role: "admin" } });
    check("admin can change another user's role", promote.status === 200 && promote.body.user.role === "admin", JSON.stringify(promote.body));
    check("role change persists", (await req("/api/users")).body.users.find((u) => u.id === operatorId).role === "admin");
    check("with two admins one can be demoted", (await req(`/api/users/${operatorId}/role`, { method: "POST", body: { role: "user" } })).status === 200);

    cookie = null; csrf = null;
    const viewerLogin = await req("/api/auth/login", { method: "POST", body: { username: "watcher", password: "watcher-long-password" } });
    csrf = viewerLogin.body.csrfToken;
    check("viewer signs in", viewerLogin.status === 200 && viewerLogin.body.user.role === "viewer", JSON.stringify(viewerLogin.body));
    check("viewer can read status", (await req("/api/status")).status === 200);
    check("viewer can read the summary", (await req("/api/summary")).status === 200);
    check("viewer can read reports", (await req("/api/reports")).status === 200);
    check("viewer can read source ips", (await req("/api/ips")).status === 200);
    check("viewer can export csv", (await fetch(`http://127.0.0.1:${APP_PORT}/api/export/records.csv`, { headers: { Cookie: cookie } })).status === 200);
    const readOnly = async (path, options) => (await req(path, options)).status === 403;
    check("viewer cannot start a sync", await readOnly("/api/sync", { method: "POST", body: {} }));
    check("viewer cannot add a mailbox", await readOnly("/api/mailboxes", { method: "POST", body: {} }));
    check("viewer cannot manage users", (await req("/api/users")).status === 403);
    check("viewer can change their own password", (await req("/api/auth/password", { method: "POST", body: { currentPassword: "watcher-long-password", newPassword: "watcher-longer-password-2" } })).status === 200);

    cookie = adminCookie; csrf = adminCsrf;
    await req(`/api/users/${viewerId}`, { method: "DELETE" });

    // === lockout ===
    cookie = null; csrf = null;
    let locked = null;
    for (let i = 0; i < 6; i += 1) {
      locked = await req("/api/auth/login", { method: "POST", body: { username: "operator", password: "wrong-password" } });
    }
    check("account locks after repeated failures", locked.status === 429, String(locked.status));
    check("correct password still refused while locked", (await req("/api/auth/login", { method: "POST", body: { username: "operator", password: "another-long-password" } })).status === 429);

    // === username enumeration ===
    const unknown = await req("/api/auth/login", { method: "POST", body: { username: "does-not-exist", password: "whatever-long" } });
    check("unknown user gives the same error as a wrong password", unknown.status === 401 && /incorrect username or password/i.test(unknown.body.error || ""), JSON.stringify(unknown.body));

    // === proxy auth is off unless explicitly enabled ===
    const spoofed = await req("/api/reports", {
      cookieOverride: null,
      // Would be honoured only if TRUST_PROXY_AUTH were on.
      method: "GET"
    });
    check("proxy header is ignored by default", spoofed.status === 401, String(spoofed.status));

    const spoofRes = await fetch(`http://127.0.0.1:${APP_PORT}/api/reports`, { headers: { "Remote-User": "admin" } });
    check("Remote-User header alone grants nothing by default", spoofRes.status === 401, String(spoofRes.status));

    // === secrets on disk ===
    const usersRaw = fs.readFileSync(path.join(DATA_DIR, "users.json"), "utf8");
    check("passwords are not stored in plaintext", !usersRaw.includes("correct-horse-battery") && !usersRaw.includes("another-long-password"));
    check("recovery codes are stored hashed", !recoveryCodes.some((c) => usersRaw.includes(c)));
  } finally {
    // The SQLite file stays locked until the child has actually exited.
    const exited = new Promise((resolve) => app.once("exit", resolve));
    app.kill();
    await exited;
    fs.rmSync(DATA_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }

  process.exit(report() ? 0 : 1);
})().catch((e) => {
  console.error("FATAL", e);
  fs.rmSync(DATA_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  process.exit(1);
});
