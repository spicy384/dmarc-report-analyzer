/**
 * User accounts, sessions and the authentication routes.
 *
 * Storage is the same flat-JSON approach as the rest of the app. State that
 * matters (users, sessions) is persisted so a restart does not sign everyone
 * out or lose accounts.
 */
const fs = require("fs");
const path = require("path");
const express = require("express");
const QRCode = require("qrcode");

const auth = require("./auth");

const SESSION_COOKIE = "dmarc_session";
const CSRF_HEADER = "x-csrf-token";

// Session lifetimes.
const IDLE_TIMEOUT_MS = 8 * 60 * 60 * 1000;      // signed out after 8h of inactivity
const ABSOLUTE_TIMEOUT_MS = 7 * 24 * 60 * 60 * 1000; // and after 7 days regardless
const PENDING_LOGIN_TTL_MS = 5 * 60 * 1000;      // window to enter an MFA code

// Brute-force protection.
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

// Methods that change state require a CSRF token.
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

// admin: everything. user: edits phones. viewer: read-only.
const ROLES = new Set(["admin", "user", "viewer"]);

function createAuth({ dataDir }) {
  const USERS_FILE = path.join(dataDir, "users.json");
  const SESSIONS_FILE = path.join(dataDir, "sessions.json");

  // Optional: let a reverse proxy (Authelia, Authentik, oauth2-proxy) assert identity.
  const trustProxyAuth = String(process.env.TRUST_PROXY_AUTH || "").toLowerCase() === "true";
  const proxyUserHeader = String(process.env.PROXY_USER_HEADER || "remote-user").toLowerCase();

  // Set this whenever HTTPS terminates in front of the app (a reverse proxy counts).
  // Deliberately not tied to NODE_ENV: a flag that silently does nothing is worse
  // than one that is simply off.
  const cookieSecure = String(process.env.COOKIE_SECURE || "").toLowerCase() === "true";

  // Pending logins live in memory only: they are short-lived by design.
  const pendingLogins = new Map();

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
    // Best effort: these files hold password hashes and TOTP secrets.
    try {
      fs.chmodSync(file, 0o600);
    } catch {
      // chmod is a no-op on some Windows setups; not fatal.
    }
  }

  const loadUsers = () => {
    const u = readJson(USERS_FILE, []);
    return Array.isArray(u) ? u : [];
  };
  const saveUsers = (users) => writeJson(USERS_FILE, users);

  const loadSessions = () => {
    const s = readJson(SESSIONS_FILE, {});
    return s && typeof s === "object" && !Array.isArray(s) ? s : {};
  };
  const saveSessions = (sessions) => writeJson(SESSIONS_FILE, sessions);

  function hasUsers() {
    return loadUsers().length > 0;
  }

  function findUser(username) {
    const target = String(username || "").trim().toLowerCase();
    return loadUsers().find((u) => u.username.toLowerCase() === target) || null;
  }

  function findUserById(id) {
    return loadUsers().find((u) => u.id === id) || null;
  }

  function updateUser(id, patch) {
    const users = loadUsers();
    const idx = users.findIndex((u) => u.id === id);
    if (idx < 0) {
      return null;
    }
    users[idx] = { ...users[idx], ...patch };
    saveUsers(users);
    return users[idx];
  }

  // --- sessions ------------------------------------------------------------

  function pruneSessions(sessions) {
    const now = Date.now();
    let changed = false;
    for (const [id, s] of Object.entries(sessions)) {
      if (now > s.expiresAt || now - s.lastSeenAt > IDLE_TIMEOUT_MS) {
        delete sessions[id];
        changed = true;
      }
    }
    return changed;
  }

  function createSession(userId) {
    const sessions = loadSessions();
    pruneSessions(sessions);

    const id = auth.randomToken(32);
    sessions[id] = {
      userId,
      csrfToken: auth.randomToken(24),
      createdAt: Date.now(),
      lastSeenAt: Date.now(),
      expiresAt: Date.now() + ABSOLUTE_TIMEOUT_MS
    };

    saveSessions(sessions);
    return { id, ...sessions[id] };
  }

  function getSession(id) {
    if (!id) {
      return null;
    }

    const sessions = loadSessions();
    const pruned = pruneSessions(sessions);
    const session = sessions[id];

    if (!session) {
      if (pruned) {
        saveSessions(sessions);
      }
      return null;
    }

    // Sliding idle window.
    session.lastSeenAt = Date.now();
    saveSessions(sessions);
    return { id, ...session };
  }

  function destroySession(id) {
    const sessions = loadSessions();
    if (sessions[id]) {
      delete sessions[id];
      saveSessions(sessions);
    }
  }

  function destroySessionsForUser(userId) {
    const sessions = loadSessions();
    let changed = false;
    for (const [id, s] of Object.entries(sessions)) {
      if (s.userId === userId) {
        delete sessions[id];
        changed = true;
      }
    }
    if (changed) {
      saveSessions(sessions);
    }
  }

  // --- cookies -------------------------------------------------------------

  function parseCookies(header) {
    const out = {};
    for (const part of String(header || "").split(";")) {
      const idx = part.indexOf("=");
      if (idx > 0) {
        out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
      }
    }
    return out;
  }

  function setSessionCookie(res, id) {
    const attrs = [
      `${SESSION_COOKIE}=${id}`,
      "Path=/",
      "HttpOnly",
      "SameSite=Lax",
      `Max-Age=${Math.floor(ABSOLUTE_TIMEOUT_MS / 1000)}`
    ];
    // Secure requires HTTPS; setting it on plain HTTP would stop sign-in working at all.
    if (cookieSecure) {
      attrs.push("Secure");
    }
    res.setHeader("Set-Cookie", attrs.join("; "));
  }

  function clearSessionCookie(res) {
    res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
  }

  // --- lockout -------------------------------------------------------------

  function isLockedOut(user) {
    return Boolean(user?.lockedUntil && Date.now() < user.lockedUntil);
  }

  function registerFailure(user) {
    const failed = (user.failedAttempts || 0) + 1;
    const patch = { failedAttempts: failed };
    if (failed >= MAX_FAILED_ATTEMPTS) {
      patch.lockedUntil = Date.now() + LOCKOUT_MS;
      patch.failedAttempts = 0;
    }
    updateUser(user.id, patch);
  }

  function clearFailures(user) {
    if (user.failedAttempts || user.lockedUntil) {
      updateUser(user.id, { failedAttempts: 0, lockedUntil: null });
    }
  }

  // --- identity resolution -------------------------------------------------

  function publicUser(user) {
    return user && {
      id: user.id,
      username: user.username,
      role: user.role,
      mfaEnrolled: Boolean(user.totpSecret && user.mfaEnrolled),
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt || null
    };
  }

  /** Resolves the caller, from a trusted proxy header if enabled, else the session cookie. */
  function resolveIdentity(req) {
    if (trustProxyAuth) {
      const name = req.headers[proxyUserHeader];
      if (name) {
        const user = findUser(name);
        if (user) {
          return { user, session: null, viaProxy: true };
        }
      }
    }

    const cookies = parseCookies(req.headers.cookie);
    const session = getSession(cookies[SESSION_COOKIE]);
    if (!session) {
      return null;
    }

    const user = findUserById(session.userId);
    if (!user) {
      destroySession(session.id);
      return null;
    }

    return { user, session, viaProxy: false };
  }

  function requireAuth(req, res, next) {
    // Before any account exists the app is unusable until setup runs.
    if (!hasUsers()) {
      return res.status(409).json({ error: "Setup required.", setupRequired: true });
    }

    const identity = resolveIdentity(req);
    if (!identity) {
      return res.status(401).json({ error: "Not signed in." });
    }

    // CSRF: cookie-authenticated state changes must echo the session token.
    // Proxy-authenticated calls are exempt because they carry no cookie.
    if (!SAFE_METHODS.has(req.method) && !identity.viaProxy) {
      const supplied = req.headers[CSRF_HEADER];
      if (!supplied || !auth.safeEqual(supplied, identity.session.csrfToken)) {
        return res.status(403).json({ error: "Invalid or missing CSRF token." });
      }
    }

    req.user = identity.user;
    req.session = identity.session;
    return next();
  }

  function requireAdmin(req, res, next) {
    if (req.user?.role !== "admin") {
      return res.status(403).json({ error: "Administrator access required." });
    }
    return next();
  }

  /** Viewers can look at everything but change nothing. */
  function requireWriter(req, res, next) {
    if (req.user?.role === "viewer") {
      return res.status(403).json({ error: "This account is read-only. Ask an administrator for the user role to make changes." });
    }
    return next();
  }

  // --- routes --------------------------------------------------------------

  const router = express.Router();

  router.get("/api/auth/me", (req, res) => {
    if (!hasUsers()) {
      return res.json({ authenticated: false, setupRequired: true });
    }

    const identity = resolveIdentity(req);
    if (!identity) {
      return res.json({ authenticated: false, setupRequired: false });
    }

    return res.json({
      authenticated: true,
      setupRequired: false,
      user: publicUser(identity.user),
      csrfToken: identity.session ? identity.session.csrfToken : null,
      viaProxy: identity.viaProxy
    });
  });

  /** First-run only: creates the initial administrator. */
  router.post("/api/auth/setup", (req, res) => {
    if (hasUsers()) {
      return res.status(409).json({ error: "Setup has already been completed." });
    }

    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");

    if (!/^[a-zA-Z0-9._-]{3,32}$/.test(username)) {
      return res.status(400).json({ error: "Username must be 3-32 characters (letters, numbers, . _ -)." });
    }
    if (password.length < 12) {
      return res.status(400).json({ error: "Password must be at least 12 characters." });
    }

    const user = {
      id: auth.randomToken(8),
      username,
      passwordHash: auth.hashPassword(password),
      role: "admin",
      totpSecret: null,
      mfaEnrolled: false,
      lastTotpCounter: 0,
      recoveryCodes: [],
      createdAt: Date.now(),
      lastLoginAt: null,
      failedAttempts: 0,
      lockedUntil: null
    };

    saveUsers([user]);

    const session = createSession(user.id);
    setSessionCookie(res, session.id);
    return res.json({ ok: true, user: publicUser(user), csrfToken: session.csrfToken });
  });

  router.post("/api/auth/login", (req, res) => {
    if (!hasUsers()) {
      return res.status(409).json({ error: "Setup required.", setupRequired: true });
    }

    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    const user = findUser(username);

    // Same response whether the user exists or not, so usernames cannot be probed.
    const invalid = () => res.status(401).json({ error: "Incorrect username or password." });

    if (!user) {
      // Spend comparable time so timing does not reveal existence.
      auth.verifyPassword(password, "scrypt$16384$8$1$00$00");
      return invalid();
    }

    if (isLockedOut(user)) {
      const mins = Math.ceil((user.lockedUntil - Date.now()) / 60000);
      return res.status(429).json({ error: `Too many failed attempts. Try again in ${mins} minute(s).` });
    }

    if (!auth.verifyPassword(password, user.passwordHash)) {
      registerFailure(user);
      return invalid();
    }

    clearFailures(user);

    if (user.mfaEnrolled && user.totpSecret) {
      const pendingToken = auth.randomToken(24);
      pendingLogins.set(pendingToken, { userId: user.id, expiresAt: Date.now() + PENDING_LOGIN_TTL_MS });
      return res.json({ ok: true, mfaRequired: true, pendingToken });
    }

    const session = createSession(user.id);
    updateUser(user.id, { lastLoginAt: Date.now() });
    setSessionCookie(res, session.id);
    return res.json({
      ok: true,
      mfaRequired: false,
      user: publicUser(user),
      csrfToken: session.csrfToken,
      mfaSetupRequired: !user.mfaEnrolled
    });
  });

  function consumePending(token) {
    const pending = pendingLogins.get(token);
    if (!pending) {
      return null;
    }
    if (Date.now() > pending.expiresAt) {
      pendingLogins.delete(token);
      return null;
    }
    return pending;
  }

  router.post("/api/auth/login/mfa", (req, res) => {
    const pending = consumePending(String(req.body?.pendingToken || ""));
    if (!pending) {
      return res.status(401).json({ error: "Sign-in expired. Start again." });
    }

    const user = findUserById(pending.userId);
    if (!user) {
      return res.status(401).json({ error: "Sign-in expired. Start again." });
    }

    if (isLockedOut(user)) {
      return res.status(429).json({ error: "Too many failed attempts. Try again later." });
    }

    const counter = auth.verifyTotp(user.totpSecret, req.body?.code);
    if (counter === null) {
      registerFailure(user);
      return res.status(401).json({ error: "Incorrect authentication code." });
    }

    // Reject codes already used: a 30s window would otherwise allow replay.
    if (counter <= (user.lastTotpCounter || 0)) {
      return res.status(401).json({ error: "That code has already been used. Wait for the next one." });
    }

    pendingLogins.delete(String(req.body.pendingToken));
    updateUser(user.id, { lastTotpCounter: counter, lastLoginAt: Date.now(), failedAttempts: 0, lockedUntil: null });

    const session = createSession(user.id);
    setSessionCookie(res, session.id);
    return res.json({ ok: true, user: publicUser(user), csrfToken: session.csrfToken });
  });

  router.post("/api/auth/login/recovery", (req, res) => {
    const pending = consumePending(String(req.body?.pendingToken || ""));
    if (!pending) {
      return res.status(401).json({ error: "Sign-in expired. Start again." });
    }

    const user = findUserById(pending.userId);
    if (!user) {
      return res.status(401).json({ error: "Sign-in expired. Start again." });
    }

    const supplied = auth.hashRecoveryCode(req.body?.code);
    const remaining = (user.recoveryCodes || []).filter((h) => h !== supplied);

    if (remaining.length === (user.recoveryCodes || []).length) {
      registerFailure(user);
      return res.status(401).json({ error: "Incorrect recovery code." });
    }

    // Single use.
    pendingLogins.delete(String(req.body.pendingToken));
    updateUser(user.id, { recoveryCodes: remaining, lastLoginAt: Date.now(), failedAttempts: 0, lockedUntil: null });

    const session = createSession(user.id);
    setSessionCookie(res, session.id);
    return res.json({ ok: true, user: publicUser(user), csrfToken: session.csrfToken, recoveryCodesRemaining: remaining.length });
  });

  router.post("/api/auth/logout", requireAuth, (req, res) => {
    if (req.session) {
      destroySession(req.session.id);
    }
    clearSessionCookie(res);
    return res.json({ ok: true });
  });

  /** Begins TOTP enrolment; nothing is stored until the code is confirmed. */
  router.post("/api/auth/mfa/setup", requireAuth, async (req, res) => {
    const secret = auth.generateTotpSecret();
    const uri = auth.buildOtpauthUri({ secret, account: req.user.username });

    // Held on the user record but not active until /confirm succeeds.
    updateUser(req.user.id, { pendingTotpSecret: secret });

    try {
      const qrDataUrl = await QRCode.toDataURL(uri, { margin: 1, width: 220 });
      return res.json({ ok: true, secret, uri, qrDataUrl });
    } catch (error) {
      return res.status(500).json({ error: `Could not render QR code: ${error.message}` });
    }
  });

  router.post("/api/auth/mfa/confirm", requireAuth, (req, res) => {
    const user = findUserById(req.user.id);
    if (!user?.pendingTotpSecret) {
      return res.status(400).json({ error: "Start enrolment first." });
    }

    const counter = auth.verifyTotp(user.pendingTotpSecret, req.body?.code);
    if (counter === null) {
      return res.status(400).json({ error: "That code did not match. Check your device's clock and try again." });
    }

    const recoveryCodes = auth.generateRecoveryCodes(10);
    updateUser(user.id, {
      totpSecret: user.pendingTotpSecret,
      pendingTotpSecret: null,
      mfaEnrolled: true,
      lastTotpCounter: counter,
      recoveryCodes: recoveryCodes.map(auth.hashRecoveryCode)
    });

    // The only time the plaintext codes are ever returned.
    return res.json({ ok: true, recoveryCodes });
  });

  router.post("/api/auth/mfa/disable", requireAuth, (req, res) => {
    const user = findUserById(req.user.id);
    if (!auth.verifyPassword(req.body?.password, user.passwordHash)) {
      return res.status(401).json({ error: "Password is incorrect." });
    }

    updateUser(user.id, { totpSecret: null, pendingTotpSecret: null, mfaEnrolled: false, recoveryCodes: [], lastTotpCounter: 0 });
    return res.json({ ok: true });
  });

  router.post("/api/auth/password", requireAuth, (req, res) => {
    const user = findUserById(req.user.id);
    const next = String(req.body?.newPassword || "");

    if (!auth.verifyPassword(req.body?.currentPassword, user.passwordHash)) {
      return res.status(401).json({ error: "Current password is incorrect." });
    }
    if (next.length < 12) {
      return res.status(400).json({ error: "New password must be at least 12 characters." });
    }

    updateUser(user.id, { passwordHash: auth.hashPassword(next) });
    return res.json({ ok: true });
  });

  // --- user management (admin) ---------------------------------------------

  router.get("/api/users", requireAuth, requireAdmin, (req, res) => {
    res.json({ users: loadUsers().map(publicUser) });
  });

  router.post("/api/users", requireAuth, requireAdmin, (req, res) => {
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    const role = ROLES.has(req.body?.role) ? req.body.role : "user";

    if (!/^[a-zA-Z0-9._-]{3,32}$/.test(username)) {
      return res.status(400).json({ error: "Username must be 3-32 characters (letters, numbers, . _ -)." });
    }
    if (password.length < 12) {
      return res.status(400).json({ error: "Password must be at least 12 characters." });
    }
    if (findUser(username)) {
      return res.status(409).json({ error: "That username is already taken." });
    }

    const users = loadUsers();
    const user = {
      id: auth.randomToken(8),
      username,
      passwordHash: auth.hashPassword(password),
      role,
      totpSecret: null,
      mfaEnrolled: false,
      lastTotpCounter: 0,
      recoveryCodes: [],
      createdAt: Date.now(),
      lastLoginAt: null,
      failedAttempts: 0,
      lockedUntil: null
    };

    users.push(user);
    saveUsers(users);
    return res.json({ ok: true, user: publicUser(user) });
  });

  router.delete("/api/users/:id", requireAuth, requireAdmin, (req, res) => {
    const id = String(req.params.id);
    const users = loadUsers();
    const target = users.find((u) => u.id === id);

    if (!target) {
      return res.status(404).json({ error: "User not found." });
    }
    if (target.id === req.user.id) {
      return res.status(400).json({ error: "You cannot delete your own account." });
    }
    if (target.role === "admin" && users.filter((u) => u.role === "admin").length === 1) {
      return res.status(400).json({ error: "Cannot remove the last administrator." });
    }

    saveUsers(users.filter((u) => u.id !== id));
    destroySessionsForUser(id);
    return res.json({ ok: true });
  });

  router.post("/api/users/:id/role", requireAuth, requireAdmin, (req, res) => {
    const role = String(req.body?.role || "");
    if (!ROLES.has(role)) {
      return res.status(400).json({ error: "Role must be admin, user or viewer." });
    }

    const users = loadUsers();
    const target = users.find((u) => u.id === String(req.params.id));
    if (!target) {
      return res.status(404).json({ error: "User not found." });
    }
    if (target.id === req.user.id) {
      return res.status(400).json({ error: "You cannot change your own role." });
    }
    if (target.role === "admin" && role !== "admin" && users.filter((u) => u.role === "admin").length === 1) {
      return res.status(400).json({ error: "Cannot demote the last administrator." });
    }

    updateUser(target.id, { role });
    return res.json({ ok: true, user: publicUser({ ...target, role }) });
  });

  /** Admin escape hatch for a user who has lost their authenticator. */
  router.post("/api/users/:id/reset-mfa", requireAuth, requireAdmin, (req, res) => {
    const target = findUserById(String(req.params.id));
    if (!target) {
      return res.status(404).json({ error: "User not found." });
    }

    updateUser(target.id, {
      totpSecret: null, pendingTotpSecret: null, mfaEnrolled: false,
      recoveryCodes: [], lastTotpCounter: 0, failedAttempts: 0, lockedUntil: null
    });
    destroySessionsForUser(target.id);
    return res.json({ ok: true });
  });

  return {
    router,
    requireAuth,
    requireAdmin,
    requireWriter,
    hasUsers,
    loadUsers,
    findUser,
    trustProxyAuth,
    proxyUserHeader,
    cookieSecure,
    SESSION_COOKIE,
    CSRF_HEADER
  };
}

module.exports = { createAuth };
