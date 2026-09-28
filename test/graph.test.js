/** Certificate credentials: the client assertion, and the token request against the mock identity endpoint. */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { createChecker } = require("./helpers/assert");
const { createMockGraph } = require("./helpers/mock-graph");
const { createGraphClient, configFromEnv, loadCertificate, certificateInfo, buildClientAssertion } = require("../graph");

const { check, report } = createChecker("graph: certificate credentials");

const certPem = fs.readFileSync(path.join(__dirname, "helpers", "test-cert.pem"), "utf8");
const keyPem = fs.readFileSync(path.join(__dirname, "helpers", "test-key.pem"), "utf8");
const encryptedKeyPem = fs.readFileSync(path.join(__dirname, "helpers", "test-key-encrypted.pem"), "utf8");
const otherKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" });

const decode = (s) => JSON.parse(Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));

(async () => {
  // --- loading ---
  const loaded = loadCertificate({ cert: certPem, key: keyPem });
  check("loads a PEM pair and reports thumbprint, subject, expiry", /^[0-9A-F]{40}$/.test(loaded.thumbprint) && /CN=dmarc-analyzer-test/.test(loaded.subject) && loaded.notAfter > Date.now() / 1000 && loaded.expired === false);
  const combined = loadCertificate({ cert: `${certPem}\n${keyPem}` });
  check("a combined PEM (cert + key in one file) works without a key field", combined.thumbprint === loaded.thumbprint);
  const enc = loadCertificate({ cert: certPem, key: encryptedKeyPem, passphrase: "fixture-pass" });
  check("an encrypted key opens with its passphrase", enc.thumbprint === loaded.thumbprint);
  const badPass = (() => { try { loadCertificate({ cert: certPem, key: encryptedKeyPem, passphrase: "nope" }); return null; } catch (e) { return e; } })();
  check("wrong passphrase is a clear error", badPass && badPass.code === "certificate" && /passphrase/.test(badPass.message), badPass && badPass.message);
  const mismatch = (() => { try { loadCertificate({ cert: certPem, key: otherKey }); return null; } catch (e) { return e; } })();
  check("key that does not match the certificate is refused", mismatch && /does not match/.test(mismatch.message));
  const junk = (() => { try { loadCertificate({ cert: "hello", key: keyPem }); return null; } catch (e) { return e; } })();
  check("junk certificate is refused", junk && /could not be read/.test(junk.message));
  const info = certificateInfo({ cert: certPem, key: otherKey });
  check("certificateInfo never throws; it carries the error", info.error && /does not match/.test(info.error) && info.thumbprint === null);
  check("certificateInfo for a good pair has no error", certificateInfo({ cert: certPem, key: keyPem }).error === null);

  // --- assertion ---
  const jwt = buildClientAssertion({ clientId: "app-1", tenantId: "tenant-1", loginBase: "https://login.test", certificate: { cert: certPem, key: keyPem }, now: () => 1_800_000_000_000 });
  const [h, c, sig] = jwt.split(".");
  const header = decode(h);
  const claims = decode(c);
  check("assertion header: RS256 with x5t thumbprint", header.alg === "RS256" && header.typ === "JWT" && header.x5t === Buffer.from(loaded.thumbprint, "hex").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
  check("assertion claims: aud is the token endpoint, iss/sub the client, 10 minute life", claims.aud === "https://login.test/tenant-1/oauth2/v2.0/token" && claims.iss === "app-1" && claims.sub === "app-1" && claims.exp - claims.nbf === 11 * 60 && claims.nbf === 1_800_000_000 - 60 && typeof claims.jti === "string");
  const x509 = new crypto.X509Certificate(certPem);
  check("assertion signature verifies with the certificate's public key", crypto.verify("sha256", Buffer.from(`${h}.${c}`), x509.publicKey, Buffer.from(sig.replace(/-/g, "+").replace(/_/g, "/"), "base64")));

  // --- token request ---
  const mock = createMockGraph({ mailbox: "dmarc@example.com", certificate: certPem });
  const { loginBase: base, graphBase } = await mock.start();
  try {
    const client = createGraphClient({ tenantId: "tenant-1", clientId: "app-1", certificate: { cert: certPem, key: keyPem }, mailbox: "dmarc@example.com", loginBase: base, graphBase });
    check("client reports certificate auth", client.authMethod() === "certificate" && client.isConfigured() && client.describe().certificate.thumbprint === loaded.thumbprint);
    check("describe never carries key material", !JSON.stringify(client.describe()).includes("PRIVATE KEY"));
    const token = await client.getToken();
    check("token issued with a client assertion and no secret", token === "mock-token" && mock.state.lastTokenRequest.client_assertion && !("client_secret" in mock.state.lastTokenRequest));

    const wrong = createGraphClient({ tenantId: "tenant-1", clientId: "app-1", certificate: { cert: certPem, key: otherKey }, mailbox: "dmarc@example.com", loginBase: base });
    const err = await wrong.getToken().catch((e) => e);
    check("mismatched key fails before the request, with code certificate", err && err.code === "certificate");

    const secretClient = createGraphClient({ tenantId: "tenant-1", clientId: "app-1", clientSecret: "s3cret", mailbox: "dmarc@example.com", loginBase: base });
    check("secret auth still works alongside", secretClient.authMethod() === "secret" && (await secretClient.getToken()) === "mock-token" && mock.state.lastTokenRequest.client_secret === "s3cret");

    const neither = createGraphClient({ tenantId: "tenant-1", clientId: "app-1", mailbox: "dmarc@example.com" });
    check("no credential: not configured, names both options", !neither.isConfigured() && neither.describe().missing.some((m) => /GRAPH_CLIENT_SECRET or GRAPH_CERT_FILE/.test(m)));
  } finally {
    await mock.stop();
  }

  // --- env ---
  const fromFiles = configFromEnv({ GRAPH_TENANT_ID: "t", GRAPH_CLIENT_ID: "c", GRAPH_CERT_FILE: path.join(__dirname, "helpers", "test-cert.pem"), GRAPH_KEY_FILE: path.join(__dirname, "helpers", "test-key-encrypted.pem"), GRAPH_KEY_PASSPHRASE: "fixture-pass", DMARC_MAILBOX: "a@b.test" });
  check("env: certificate files are read", fromFiles.certificate && fromFiles.certificate.cert.includes("BEGIN CERTIFICATE") && fromFiles.certificate.passphrase === "fixture-pass" && fromFiles.certificateError === null);
  const missingFile = configFromEnv({ GRAPH_CERT_FILE: path.join(__dirname, "nope.pem") });
  check("env: unreadable file is reported, not thrown", missingFile.certificate === null && /Could not read/.test(missingFile.certificateError));
  const inline = configFromEnv({ GRAPH_CERT_PEM: certPem, GRAPH_KEY_PEM: keyPem });
  check("env: inline PEM accepted", inline.certificate && inline.certificate.key === keyPem);
  const errClient = createGraphClient({ tenantId: "t", clientId: "c", clientSecret: "s", certificateError: "Could not read the certificate files: boom", mailbox: "a@b.test" });
  const errTok = await errClient.getToken().catch((e) => e);
  check("env: a certificate read error surfaces on the token request", errTok && /Could not read/.test(errTok.message));

  process.exitCode = report() ? 0 : 1;
})().catch((e) => { console.error(e); process.exitCode = 1; });
