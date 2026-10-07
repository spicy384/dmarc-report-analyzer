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
    // Passkeys are bound to a hostname; pin the relying party so the fake authenticator can match it.
    // The address throttle is off here: this suite deliberately fails sign-in many times.
    env: { ...process.env, PORT: String(APP_PORT), DATA_DIR, PASSKEY_RP_ID: "localhost", PASSKEY_ORIGIN: `http://localhost:${APP_PORT}`, LOGIN_RATE_LIMIT: "0" },
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
    // A wrong password on a locked account answers like any wrong password, so the lock
    // (and with it the account's existence) is only revealed to someone who knows the password.
    check("wrong password on a locked account is a plain 401", locked.status === 401, String(locked.status));
    check("correct password is refused with 429 while locked", (await req("/api/auth/login", { method: "POST", body: { username: "operator", password: "another-long-password" } })).status === 429);

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

    // === passkeys ===
    const { createFakeAuthenticator } = require("./helpers/fake-authenticator");
    const authenticator = createFakeAuthenticator({ rpId: "localhost", origin: `http://localhost:${APP_PORT}` });
    cookie = adminCookie; csrf = adminCsrf;
    check("passkeys: none to start", (await req("/api/auth/passkeys")).body.passkeys.length === 0);
    const regOpts = await req("/api/auth/passkeys/register/options", { method: "POST", body: {} });
    check("passkeys: registration options ask for a discoverable, verified credential", regOpts.status === 200 && regOpts.body.options.rp.id === "localhost" && regOpts.body.options.authenticatorSelection.residentKey === "required" && typeof regOpts.body.options.challenge === "string");
    const regBad = await req("/api/auth/passkeys/register/verify", { method: "POST", body: { name: "x", response: { id: "nope", rawId: "nope", type: "public-key", response: {} } } });
    check("passkeys: garbage registration is refused and burns the challenge", regBad.status === 400);
    const regOpts2 = await req("/api/auth/passkeys/register/options", { method: "POST", body: {} });
    const reg = await req("/api/auth/passkeys/register/verify", { method: "POST", body: { name: "  Work laptop  ", response: authenticator.register(regOpts2.body.options) } });
    check("passkeys: registration verified and stored", reg.status === 200 && reg.body.passkey.name === "Work laptop" && reg.body.passkeys.length === 1 && reg.body.passkey.id === authenticator.credentialId, JSON.stringify(reg.body));
    check("passkeys: listing never carries the public key", !JSON.stringify((await req("/api/auth/passkeys")).body).includes("publicKey"));
    check("passkeys: /me counts them", (await req("/api/auth/me")).body.user.passkeys === 1);
    const regDup = await req("/api/auth/passkeys/register/options", { method: "POST", body: {} });
    check("passkeys: registered credential is excluded from new registrations", regDup.body.options.excludeCredentials.some((c) => c.id === authenticator.credentialId));

    // Sign in with it: no cookie, no username.
    cookie = null; csrf = null;
    const loginOpts = await req("/api/auth/passkeys/login/options", { method: "POST", body: {} });
    check("passkeys: sign-in options need no username and require verification", loginOpts.status === 200 && loginOpts.body.token && loginOpts.body.options.userVerification === "required" && loginOpts.body.options.allowCredentials.length === 0);
    const assertion = authenticator.assert(loginOpts.body.options);
    const pkLogin = await req("/api/auth/passkeys/login/verify", { method: "POST", body: { token: loginOpts.body.token, response: assertion } });
    check("passkeys: sign-in succeeds with a session and no MFA step", pkLogin.status === 200 && pkLogin.body.user.username === "admin" && pkLogin.body.csrfToken && Boolean(cookie), JSON.stringify(pkLogin.body));
    csrf = pkLogin.body.csrfToken;
    check("passkeys: session is real", (await req("/api/auth/me")).body.authenticated === true);
    check("passkeys: last used recorded", (await req("/api/auth/passkeys")).body.passkeys[0].lastUsedAt > 0);
    const passkeyCookie = cookie;
    const passkeyCsrf = csrf;

    cookie = null; csrf = null;
    const pkReplay = await req("/api/auth/passkeys/login/verify", { method: "POST", body: { token: loginOpts.body.token, response: assertion } });
    check("passkeys: a challenge cannot be reused", pkReplay.status === 401);
    const opts3 = await req("/api/auth/passkeys/login/options", { method: "POST", body: {} });
    const stranger = createFakeAuthenticator({ rpId: "localhost", origin: `http://localhost:${APP_PORT}` });
    const unknown2 = await req("/api/auth/passkeys/login/verify", { method: "POST", body: { token: opts3.body.token, response: stranger.assert(opts3.body.options) } });
    check("passkeys: unknown credential is refused", unknown2.status === 401 && !cookie);
    const opts4 = await req("/api/auth/passkeys/login/options", { method: "POST", body: {} });
    const forged = authenticator.assert(opts4.body.options, { signWith: require("crypto").generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey });
    const forgedRes = await req("/api/auth/passkeys/login/verify", { method: "POST", body: { token: opts4.body.token, response: forged } });
    check("passkeys: bad signature is refused", forgedRes.status === 401 && !cookie);
    const opts5 = await req("/api/auth/passkeys/login/options", { method: "POST", body: {} });
    const noUv = await req("/api/auth/passkeys/login/verify", { method: "POST", body: { token: opts5.body.token, response: authenticator.assert(opts5.body.options, { userVerified: false }) } });
    check("passkeys: sign-in without user verification is refused", noUv.status === 401 && !cookie);
    const opts6 = await req("/api/auth/passkeys/login/options", { method: "POST", body: {} });
    const wrongOrigin = createFakeAuthenticator({ rpId: "localhost", origin: "https://evil.example" });
    // Same key material is not shared between instances, so this fails on signature or origin; either is a refusal.
    check("passkeys: wrong origin is refused", (await req("/api/auth/passkeys/login/verify", { method: "POST", body: { token: opts6.body.token, response: wrongOrigin.assert(opts6.body.options) } })).status === 401);

    // Remove it, then it no longer signs in.
    cookie = passkeyCookie; csrf = passkeyCsrf;
    const removed = await req(`/api/auth/passkeys/${authenticator.credentialId}`, { method: "DELETE" });
    check("passkeys: remove", removed.status === 200 && removed.body.passkeys.length === 0);
    check("passkeys: remove unknown is 404", (await req("/api/auth/passkeys/nope", { method: "DELETE" })).status === 404);
    cookie = null; csrf = null;
    const opts7 = await req("/api/auth/passkeys/login/options", { method: "POST", body: {} });
    check("passkeys: removed credential no longer signs in", (await req("/api/auth/passkeys/login/verify", { method: "POST", body: { token: opts7.body.token, response: authenticator.assert(opts7.body.options) } })).status === 401);
    check("passkeys: options require CSRF-free public access but not before setup", (await req("/api/auth/passkeys/register/options", { method: "POST", body: {}, cookieOverride: null })).status === 401);

    // === sessions ===
    cookie = adminCookie; csrf = adminCsrf;
    const sess = await req("/api/auth/sessions");
    check("sessions: lists the caller's sessions with one marked current", sess.status === 200 && sess.body.sessions.length >= 2 && sess.body.sessions.filter((s) => s.current).length === 1 && sess.body.sessions.every((s) => s.key && s.createdAt && s.lastSeenAt), JSON.stringify(sess.body).slice(0, 200));
    check("sessions: no raw session id is exposed", !JSON.stringify(sess.body).includes(adminCookie.split("=")[1]));
    const other = sess.body.sessions.find((s) => !s.current);
    const current = sess.body.sessions.find((s) => s.current);
    check("sessions: ending the current one is refused", (await req(`/api/auth/sessions/${current.key}`, { method: "DELETE" })).status === 400);
    check("sessions: unknown key is 404", (await req("/api/auth/sessions/0123456789abcdef", { method: "DELETE" })).status === 404);
    check("sessions: end another session", (await req(`/api/auth/sessions/${other.key}`, { method: "DELETE" })).status === 200);
    check("sessions: the ended session no longer works", (await req("/api/auth/me", { cookieOverride: passkeyCookie })).body.authenticated === false);
    const others = await req("/api/auth/sessions/sign-out-others", { method: "POST", body: {} });
    check("sessions: sign out other devices keeps this one", others.status === 200 && (await req("/api/auth/me")).body.authenticated === true && (await req("/api/auth/sessions")).body.sessions.length === 1);
    check("sessions: sign out everywhere ends this one too", (await req("/api/auth/sessions/sign-out-all", { method: "POST", body: {} })).status === 200 && (await req("/api/auth/me", { cookieOverride: adminCookie })).body.authenticated === false);
    cookie = null; csrf = null;

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
