/**
 * Authentication primitives: password hashing, one-time passwords and recovery
 * codes. Everything here is built on node's crypto module - no external deps.
 */
const crypto = require("crypto");

// --- password hashing ------------------------------------------------------

const SCRYPT_N = 16384; // CPU/memory cost
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 64;
const SALT_BYTES = 16;

function scryptHash(password, salt) {
  return crypto.scryptSync(String(password), salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    // scrypt needs headroom above the default 32MB for these parameters.
    maxmem: 256 * 1024 * 1024
  });
}

/** Returns a self-describing string so parameters can change later without breaking old hashes. */
function hashPassword(password) {
  const salt = crypto.randomBytes(SALT_BYTES);
  const hash = scryptHash(password, salt);
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString("hex")}$${hash.toString("hex")}`;
}

function verifyPassword(password, stored) {
  try {
    const parts = String(stored || "").split("$");
    if (parts.length !== 6 || parts[0] !== "scrypt") {
      return false;
    }

    const [, n, r, p, saltHex, hashHex] = parts;
    const salt = Buffer.from(saltHex, "hex");
    const expected = Buffer.from(hashHex, "hex");
    const actual = crypto.scryptSync(String(password), salt, expected.length, {
      N: Number(n),
      r: Number(r),
      p: Number(p),
      maxmem: 256 * 1024 * 1024
    });

    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

// --- base32 (RFC 4648, no padding) -----------------------------------------

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let out = "";

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    out += B32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return out;
}

function base32Decode(input) {
  const clean = String(input).toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const out = [];

  for (const char of clean) {
    const idx = B32_ALPHABET.indexOf(char);
    if (idx === -1) {
      throw new Error("Invalid base32 character in secret.");
    }

    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(out);
}

// --- HOTP / TOTP -----------------------------------------------------------

/** RFC 4226 HOTP. `counter` is a non-negative integer. */
function hotp(secretBuffer, counter, digits = 6, algorithm = "sha1") {
  const counterBuf = Buffer.alloc(8);
  // Split across two 32-bit writes: counters can exceed 2^32.
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter >>> 0, 4);

  const digest = crypto.createHmac(algorithm, secretBuffer).update(counterBuf).digest();

  // Dynamic truncation (RFC 4226 section 5.3).
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
    | ((digest[offset + 1] & 0xff) << 16)
    | ((digest[offset + 2] & 0xff) << 8)
    | (digest[offset + 3] & 0xff);

  return String(binary % 10 ** digits).padStart(digits, "0");
}

/** RFC 6238 TOTP. */
function totp(secretBase32, { time = Date.now(), period = 30, digits = 6, algorithm = "sha1" } = {}) {
  const counter = Math.floor(time / 1000 / period);
  return hotp(base32Decode(secretBase32), counter, digits, algorithm);
}

/**
 * Verifies a TOTP code, allowing `window` steps of clock drift either side.
 * Returns the matched counter so callers can reject replays, or null on failure.
 */
function verifyTotp(secretBase32, token, { time = Date.now(), period = 30, digits = 6, window = 1, algorithm = "sha1" } = {}) {
  const clean = String(token || "").replace(/\s+/g, "");
  if (!new RegExp(`^\\d{${digits}}$`).test(clean)) {
    return null;
  }

  const secret = base32Decode(secretBase32);
  const current = Math.floor(time / 1000 / period);

  for (let drift = -window; drift <= window; drift += 1) {
    const counter = current + drift;
    if (counter < 0) {
      continue;
    }

    const expected = hotp(secret, counter, digits, algorithm);
    // Constant-time compare so a timing side channel cannot leak digits.
    if (expected.length === clean.length
      && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(clean))) {
      return counter;
    }
  }

  return null;
}

function generateTotpSecret(bytes = 20) {
  return base32Encode(crypto.randomBytes(bytes));
}

/** otpauth:// URI consumed by authenticator apps and encoded into the QR. */
function buildOtpauthUri({ secret, account, issuer = "DMARC Report Analyzer", period = 30, digits = 6, algorithm = "SHA1" }) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm,
    digits: String(digits),
    period: String(period)
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// --- recovery codes --------------------------------------------------------

/** Codes are high-entropy, so a fast hash is sufficient (unlike passwords). */
function hashRecoveryCode(code) {
  return crypto.createHash("sha256").update(normalizeRecoveryCode(code)).digest("hex");
}

function normalizeRecoveryCode(code) {
  return String(code || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function generateRecoveryCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i += 1) {
    // 10 bytes -> 16 base32 chars, formatted in two groups for readability.
    const raw = base32Encode(crypto.randomBytes(10)).toLowerCase().slice(0, 16);
    codes.push(`${raw.slice(0, 8)}-${raw.slice(8)}`);
  }
  return codes;
}

// --- misc ------------------------------------------------------------------

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

/** Length-safe constant-time string comparison. */
function safeEqual(a, b) {
  const bufA = Buffer.from(String(a ?? ""));
  const bufB = Buffer.from(String(b ?? ""));
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

module.exports = {
  hashPassword,
  verifyPassword,
  base32Encode,
  base32Decode,
  hotp,
  totp,
  verifyTotp,
  generateTotpSecret,
  buildOtpauthUri,
  generateRecoveryCodes,
  hashRecoveryCode,
  normalizeRecoveryCode,
  randomToken,
  safeEqual
};
