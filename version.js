/**
 * Which version is running, and whether a newer image has been published. The
 * version comes from package.json; the commit and build date are baked into the
 * image by the workflow (APP_COMMIT, APP_BUILD_DATE). Once a day the checker lists
 * the tags of the image on GitHub Container Registry (anonymous pull token, the
 * package is public) and compares the highest semver tag with ours. Nothing but
 * the image name leaves the host; set UPDATE_CHECK=false to never ask.
 */
const CHECK_EVERY_MS = 24 * 60 * 60 * 1000;
const FIRST_CHECK_MS = 90 * 1000;

function parseSemver(tag) {
  const m = String(tag || "").match(/^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/);
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]), pre: m[4] || null, text: `${m[1]}.${m[2]}.${m[3]}${m[4] ? `-${m[4]}` : ""}` };
}

/** Negative when a < b. Pre-releases sort below the release they precede. */
function compareSemver(a, b) {
  for (const k of ["major", "minor", "patch"]) {
    if (a[k] !== b[k]) return a[k] - b[k];
  }
  if (a.pre === b.pre) return 0;
  if (a.pre === null) return 1;
  if (b.pre === null) return -1;
  return a.pre < b.pre ? -1 : 1;
}

/** Splits "ghcr.io/owner/name" into the registry host and the repository path. */
function splitImage(image) {
  const [host, ...rest] = String(image).split("/");
  return { host, repository: rest.join("/") };
}

function createUpdateChecker({ version, commit = null, buildDate = null, image = "ghcr.io/spicy384/dmarc-report-analyzer", enabled = true, fetchImpl = globalThis.fetch, now = Date.now, logger = console, timeoutMs = 10000 } = {}) {
  const current = parseSemver(version);
  let timer = null;
  const EMPTY = { checkedAt: null, latest: null, updateAvailable: false, error: null, tags: 0 };
  let last = { ...EMPTY };
  // `enabled` may be a function, so a setting changed at runtime takes effect at once.
  const isEnabled = () => Boolean(typeof enabled === "function" ? enabled() : enabled);

  async function fetchJson(url, headers = {}) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchImpl(url, { headers: { Accept: "application/json", ...headers }, signal: controller.signal });
      if (!res.ok) throw new Error(`HTTP ${res.status} from ${new URL(url).host}`);
      return res.json();
    } finally {
      clearTimeout(t);
    }
  }

  /** Lists the image's tags and remembers the highest release. Never throws. */
  async function check() {
    if (!isEnabled()) return describe();
    const { host, repository } = splitImage(image);
    try {
      const token = await fetchJson(`https://${host}/token?scope=repository:${repository}:pull`);
      const list = await fetchJson(`https://${host}/v2/${repository}/tags/list`, { Authorization: `Bearer ${token.token}` });
      const releases = (list.tags || []).map(parseSemver).filter((v) => v && v.pre === null).sort(compareSemver);
      const latest = releases.length ? releases[releases.length - 1] : null;
      last = {
        checkedAt: Math.floor(now() / 1000),
        latest: latest ? latest.text : null,
        updateAvailable: Boolean(latest && current && compareSemver(latest, current) > 0),
        error: null,
        tags: (list.tags || []).length
      };
    } catch (error) {
      last = { ...last, checkedAt: Math.floor(now() / 1000), error: error.name === "AbortError" ? "timed out" : error.message };
      logger.warn?.(`update check: ${last.error}`);
    }
    return describe();
  }

  function describe() {
    // While switched off, an earlier answer is not shown: it would only go stale.
    return { version, commit, buildDate, image, enabled: isEnabled(), ...(isEnabled() ? last : EMPTY) };
  }

  /** Forgets the last answer (used when the check is switched off). */
  function forget() {
    last = { ...EMPTY };
  }

  // The timers always run; each tick does nothing while the check is switched off.
  function start() {
    if (timer) return;
    const first = setTimeout(() => { check(); }, FIRST_CHECK_MS);
    if (typeof first.unref === "function") first.unref();
    timer = setInterval(() => { check(); }, CHECK_EVERY_MS);
    if (typeof timer.unref === "function") timer.unref();
  }

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  return { check, describe, forget, start, stop };
}

module.exports = { createUpdateChecker, parseSemver, compareSemver, splitImage };
