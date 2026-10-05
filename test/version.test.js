/** Version reporting and the registry update check against a fake ghcr. */
const { createChecker } = require("./helpers/assert");
const { createUpdateChecker, parseSemver, compareSemver, splitImage } = require("../version");

const { check, report } = createChecker("Version: semver and update check");

check("parseSemver: tags with and without v, pre-releases, junk", parseSemver("v1.2.3").text === "1.2.3" && parseSemver("1.2.3-rc.1").pre === "rc.1" && parseSemver("latest") === null && parseSemver("sha-abc1234") === null && parseSemver("1.2") === null);
check("compareSemver: numeric order and pre-release below release", compareSemver(parseSemver("1.10.0"), parseSemver("1.9.9")) > 0 && compareSemver(parseSemver("1.0.0-rc.1"), parseSemver("1.0.0")) < 0 && compareSemver(parseSemver("2.0.0"), parseSemver("2.0.0")) === 0);
check("splitImage", JSON.stringify(splitImage("ghcr.io/spicy384/dmarc-report-analyzer")) === JSON.stringify({ host: "ghcr.io", repository: "spicy384/dmarc-report-analyzer" }));

let tags = ["latest", "sha-abc1234", "1.0.0", "1.1.0", "1.1", "1.2.0-rc.1"];
const calls = [];
const fakeFetch = async (url, options) => {
  calls.push({ url, auth: options && options.headers && options.headers.Authorization });
  if (url.includes("/token?")) return { ok: true, json: async () => ({ token: "anon-token" }) };
  if (url.endsWith("/tags/list")) return { ok: true, json: async () => ({ name: "spicy384/dmarc-report-analyzer", tags }) };
  return { ok: false, status: 404, json: async () => ({}) };
};

(async () => {
  const c = createUpdateChecker({ version: "1.0.0", commit: "abc1234def", buildDate: "2026-10-02", fetchImpl: fakeFetch, now: () => 1_790_000_000_000, logger: { warn() {} } });
  check("describe before any check", c.describe().version === "1.0.0" && c.describe().commit === "abc1234def" && c.describe().checkedAt === null && c.describe().updateAvailable === false);
  const r = await c.check();
  check("check: anonymous pull token then the tag list", calls.length === 2 && calls[0].url === "https://ghcr.io/token?scope=repository:spicy384/dmarc-report-analyzer:pull" && calls[1].url === "https://ghcr.io/v2/spicy384/dmarc-report-analyzer/tags/list" && calls[1].auth === "Bearer anon-token");
  check("check: highest release wins, pre-release and non-semver tags ignored", r.latest === "1.1.0" && r.updateAvailable === true && r.tags === 6 && r.error === null && r.checkedAt === 1_790_000_000);
  tags = ["latest", "1.0.0"];
  const r2 = await c.check();
  check("check: up to date", r2.latest === "1.0.0" && r2.updateAvailable === false);
  tags = ["latest", "sha-1"];
  const r3 = await c.check();
  check("check: no releases tagged yet", r3.latest === null && r3.updateAvailable === false);

  const failing = createUpdateChecker({ version: "1.0.0", fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({}) }), logger: { warn() {} } });
  const f = await failing.check();
  check("check: registry failure is recorded, never thrown", f.error && /HTTP 503/.test(f.error) && f.updateAvailable === false);

  const off = createUpdateChecker({ version: "1.0.0", enabled: false, fetchImpl: async () => { throw new Error("must not be called"); } });
  check("disabled: no network, describe says so", (await off.check()).enabled === false && (await off.check()).checkedAt === null);

  // A setting changed at runtime: `enabled` as a function is read on every call.
  let allowed = true;
  let fetches = 0;
  tags = ["1.0.0", "1.3.0"];
  const dynamic = createUpdateChecker({ version: "1.0.0", enabled: () => allowed, fetchImpl: async (url, options) => { fetches += 1; return fakeFetch(url, options); }, logger: { warn() {} } });
  const on = await dynamic.check();
  check("dynamic: on, so it asks and finds the release", on.enabled === true && on.updateAvailable === true && on.latest === "1.3.0" && fetches === 2);
  allowed = false;
  const hidden = dynamic.describe();
  check("dynamic: switched off, the earlier answer is no longer shown", hidden.enabled === false && hidden.updateAvailable === false && hidden.latest === null && hidden.checkedAt === null);
  await dynamic.check();
  check("dynamic: switched off, no request is made", fetches === 2);
  dynamic.forget();
  allowed = true;
  check("dynamic: forget() cleared the answer for when it is switched back on", dynamic.describe().enabled === true && dynamic.describe().latest === null);

  process.exit(report() ? 0 : 1);
})();
