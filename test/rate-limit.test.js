/** Address-based sign-in throttle: counts failures only, blocks for the window, forgets afterwards. */
const { createChecker } = require("./helpers/assert");
const { createRateLimiter, clientAddress } = require("../rate-limit");

const { check, report } = createChecker("Rate limit: failures per address");

let clock = 1_000_000;
const limiter = createRateLimiter({ windowMs: 60_000, maxFailures: 3, now: () => clock });

/** Runs the middleware against a fake request and finishes the response with a status. */
function attempt(ip, status) {
  const req = { headers: {}, ip };
  const listeners = {};
  const res = {
    statusCode: 200,
    headers: {},
    body: null,
    setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
    on(event, fn) { listeners[event] = fn; }
  };
  let passed = false;
  limiter.middleware(req, res, () => { passed = true; });
  if (passed) {
    res.statusCode = status;
    listeners.finish();
  }
  return { passed, status: res.statusCode, retryAfter: res.headers["Retry-After"], body: res.body };
}

check("clientAddress: first X-Forwarded-For hop wins, else req.ip", clientAddress({ headers: { "x-forwarded-for": "203.0.113.5, 10.0.0.1" }, ip: "10.0.0.1" }) === "203.0.113.5" && clientAddress({ headers: {}, ip: "::1" }) === "::1");
check("successes never count", [1, 2, 3, 4, 5].every(() => attempt("1.1.1.1", 200).passed) && limiter.retryAfter("1.1.1.1") === 0);
attempt("2.2.2.2", 401);
attempt("2.2.2.2", 401);
check("below the limit requests pass", attempt("2.2.2.2", 401).passed === true);
const blocked = attempt("2.2.2.2", 401);
check("fourth attempt within the window is refused with Retry-After", blocked.passed === false && blocked.status === 429 && Number(blocked.retryAfter) > 0 && /Too many failed sign-in attempts/.test(blocked.body.error), JSON.stringify(blocked));
check("another address is unaffected", attempt("3.3.3.3", 401).passed === true);
check("a 429 itself is not counted as a failure", limiter.retryAfter("2.2.2.2") > 0 && attempt("2.2.2.2", 401).passed === false);
clock += 61_000;
check("after the window the address is free again", limiter.retryAfter("2.2.2.2") === 0 && attempt("2.2.2.2", 401).passed === true);
check("server errors (5xx) do not count", attempt("4.4.4.4", 500).passed && attempt("4.4.4.4", 503).passed && attempt("4.4.4.4", 500).passed && attempt("4.4.4.4", 500).passed && limiter.retryAfter("4.4.4.4") === 0);
limiter.reset("2.2.2.2");
limiter.prune();
check("prune drops idle addresses", limiter.size() <= 3);

process.exit(report() ? 0 : 1);
