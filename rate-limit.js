/**
 * Per-client rate limiting for the sign-in endpoints. Accounts already lock after
 * a few wrong passwords; this adds a second gate keyed by client address, so one
 * machine cannot spray guesses across many usernames (or lock everyone out on
 * purpose), and so unknown usernames, which no account lockout covers, are
 * throttled too. Only failed attempts count: a user who signs in correctly is
 * never slowed down, and a shared office address only suffers for its own
 * mistakes. Everything lives in memory; a restart forgets it, which is fine.
 */
const DEFAULT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_MAX_FAILURES = 20;

function clientAddress(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return forwarded || req.ip || req.socket?.remoteAddress || "unknown";
}

function createRateLimiter({ windowMs = DEFAULT_WINDOW_MS, maxFailures = DEFAULT_MAX_FAILURES, now = Date.now, keyFor = clientAddress } = {}) {
  const buckets = new Map(); // key -> { failures: [timestamps], blockedUntil }

  function bucket(key) {
    let b = buckets.get(key);
    if (!b) {
      b = { failures: [], blockedUntil: 0 };
      buckets.set(key, b);
    }
    const cutoff = now() - windowMs;
    b.failures = b.failures.filter((t) => t > cutoff);
    return b;
  }

  /** Seconds the key must still wait, or 0. */
  function retryAfter(key) {
    const b = bucket(key);
    if (b.blockedUntil > now()) return Math.ceil((b.blockedUntil - now()) / 1000);
    if (b.failures.length >= maxFailures) {
      b.blockedUntil = b.failures[0] + windowMs;
      return Math.max(1, Math.ceil((b.blockedUntil - now()) / 1000));
    }
    return 0;
  }

  function recordFailure(key) {
    bucket(key).failures.push(now());
  }

  function reset(key) {
    buckets.delete(key);
  }

  /** Drops idle buckets so the map does not grow with every scanner that passes by. */
  function prune() {
    for (const [key, b] of buckets) {
      if (b.blockedUntil <= now() && !b.failures.some((t) => t > now() - windowMs)) buckets.delete(key);
    }
  }

  /** Express middleware: 429 while blocked; afterwards counts a 4xx answer as a failure. */
  function middleware(req, res, next) {
    const key = keyFor(req);
    const wait = retryAfter(key);
    if (wait > 0) {
      res.setHeader("Retry-After", String(wait));
      return res.status(429).json({ error: `Too many failed sign-in attempts from your address. Try again in ${wait >= 120 ? `${Math.ceil(wait / 60)} minutes` : `${wait} seconds`}.` });
    }
    res.on("finish", () => {
      if (res.statusCode >= 400 && res.statusCode < 500 && res.statusCode !== 429) recordFailure(key);
      if (buckets.size > 10000) prune();
    });
    next();
  }

  return { middleware, retryAfter, recordFailure, reset, prune, size: () => buckets.size, clientAddress: keyFor };
}

module.exports = { createRateLimiter, clientAddress, DEFAULT_WINDOW_MS, DEFAULT_MAX_FAILURES };
