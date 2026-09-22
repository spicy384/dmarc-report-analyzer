/**
 * Optional HTTPS support.
 *
 * Three modes, decided by environment:
 *   - TLS_CERT + TLS_KEY set   -> use that certificate ("provided")
 *   - TLS_ENABLED=true         -> generate and reuse a self-signed cert ("self-signed")
 *   - otherwise                -> plain HTTP
 *
 * The generated certificate exists to encrypt the hop between a reverse proxy and
 * this app. Proxies do not verify upstream certificates by default, so a self-signed
 * one is sufficient there - but it is NOT suitable for browsers connecting directly,
 * which will warn. Supply a real certificate via TLS_CERT/TLS_KEY for that.
 */
const { execFileSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

// Long enough to be practical, short enough to match public-CA norms.
const CERT_DAYS = 825;
// Regenerate before it actually lapses so a long-running container never serves an expired cert.
const RENEW_BEFORE_MS = 30 * 24 * 60 * 60 * 1000;

function isTrue(value) {
  return String(value || "").toLowerCase() === "true";
}

function opensslAvailable() {
  try {
    execFileSync("openssl", ["version"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

/** Hostnames and IPs the certificate should be valid for. */
function subjectAltNames() {
  const hosts = new Set(["localhost"]);
  const ips = new Set(["127.0.0.1"]);

  for (const entry of String(process.env.TLS_HOSTS || "").split(",")) {
    const clean = entry.trim();
    if (!clean) {
      continue;
    }
    // Bare IPv4 goes in as an IP SAN; anything else as a DNS SAN.
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) {
      ips.add(clean);
    } else {
      hosts.add(clean);
    }
  }

  // The container/host name is how a proxy on a shared Docker network reaches us.
  const hostname = os.hostname();
  if (hostname) {
    hosts.add(hostname);
  }

  return {
    hosts: [...hosts],
    ips: [...ips],
    san: [...[...hosts].map((h) => `DNS:${h}`), ...[...ips].map((i) => `IP:${i}`)].join(",")
  };
}

function certNeedsRenewal(certPath) {
  try {
    const { X509Certificate } = require("crypto");
    const cert = new X509Certificate(fs.readFileSync(certPath));
    return new Date(cert.validTo).getTime() - Date.now() < RENEW_BEFORE_MS;
  } catch {
    // Unreadable or unparseable: treat as needing regeneration.
    return true;
  }
}

function generateSelfSigned(dir) {
  if (!opensslAvailable()) {
    throw new Error(
      "TLS_ENABLED is set but the 'openssl' command is not available, so a self-signed "
      + "certificate cannot be generated. Install openssl, or supply TLS_CERT and TLS_KEY."
    );
  }

  fs.mkdirSync(dir, { recursive: true });
  const keyPath = path.join(dir, "key.pem");
  const certPath = path.join(dir, "cert.pem");
  const { san, hosts } = subjectAltNames();

  execFileSync("openssl", [
    "req", "-x509",
    "-newkey", "rsa:2048",
    "-keyout", keyPath,
    "-out", certPath,
    "-days", String(CERT_DAYS),
    "-nodes",
    "-sha256",
    "-subj", `/CN=${hosts[0] === "localhost" && hosts[1] ? hosts[1] : hosts[0]}`,
    "-addext", `subjectAltName=${san}`,
    "-addext", "basicConstraints=critical,CA:FALSE",
    "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
    "-addext", "extendedKeyUsage=serverAuth"
  ], { stdio: "pipe" });

  try {
    fs.chmodSync(keyPath, 0o600);
  } catch {
    // chmod is a no-op on some Windows setups.
  }

  return { keyPath, certPath };
}

/**
 * Returns null for plain HTTP, or { key, cert, mode, detail } to serve HTTPS.
 * Throws with an actionable message when TLS is requested but cannot be set up.
 */
function resolveTlsOptions({ dataDir }) {
  const certEnv = String(process.env.TLS_CERT || "").trim();
  const keyEnv = String(process.env.TLS_KEY || "").trim();

  if (certEnv || keyEnv) {
    if (!certEnv || !keyEnv) {
      throw new Error("TLS_CERT and TLS_KEY must both be set, or neither.");
    }
    for (const [label, file] of [["TLS_CERT", certEnv], ["TLS_KEY", keyEnv]]) {
      if (!fs.existsSync(file)) {
        throw new Error(`${label} points at a file that does not exist: ${file}`);
      }
    }

    return {
      mode: "provided",
      key: fs.readFileSync(keyEnv),
      cert: fs.readFileSync(certEnv),
      detail: certEnv
    };
  }

  if (!isTrue(process.env.TLS_ENABLED)) {
    return null;
  }

  const dir = path.join(dataDir, "tls");
  const keyPath = path.join(dir, "key.pem");
  const certPath = path.join(dir, "cert.pem");

  let generated = false;
  if (!fs.existsSync(keyPath) || !fs.existsSync(certPath) || certNeedsRenewal(certPath)) {
    generateSelfSigned(dir);
    generated = true;
  }

  return {
    mode: "self-signed",
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
    detail: `${certPath}${generated ? " (generated)" : " (existing)"}`
  };
}

module.exports = { resolveTlsOptions, subjectAltNames, opensslAvailable, CERT_DAYS };
