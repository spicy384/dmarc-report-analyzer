/**
 * A software authenticator for the passkey tests: builds the same registration
 * and assertion responses a browser would hand back, signed with a P-256 key,
 * so the server's WebAuthn verification runs for real without a device.
 */
const crypto = require("crypto");

const b64url = (buf) => Buffer.from(buf).toString("base64url");

// Enough CBOR to encode an attestation object: maps, text, bytes, small ints, negatives.
function cbor(value) {
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (typeof value === "string") { const b = Buffer.from(value, "utf8"); return Buffer.concat([head(3, b.length), b]); }
  if (typeof value === "number" && Number.isInteger(value)) return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (value instanceof Map) {
    const parts = [head(5, value.size)];
    for (const [k, v] of value) parts.push(cbor(k), cbor(v));
    return Buffer.concat(parts);
  }
  if (value && typeof value === "object") {
    const keys = Object.keys(value);
    const parts = [head(5, keys.length)];
    for (const k of keys) parts.push(cbor(k), cbor(value[k]));
    return Buffer.concat(parts);
  }
  throw new Error(`cbor: unsupported value ${String(value)}`);
}

function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}

function createFakeAuthenticator({ rpId, origin }) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const credentialId = crypto.randomBytes(16);
  let counter = 0;
  const rpIdHash = crypto.createHash("sha256").update(rpId).digest();

  function clientData(type, challenge) {
    return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }), "utf8");
  }

  /** The response to navigator.credentials.create() for the given options. */
  function register(options, { userVerified = true } = {}) {
    // COSE_Key for ES256: kty EC2 (1:2), alg ES256 (3:-7), crv P-256 (-1:1), x (-2), y (-3).
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]));
    const flags = 0x41 | (userVerified ? 0x04 : 0); // UP + AT (+ UV)
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32BE(counter);
    const credIdLen = Buffer.alloc(2);
    credIdLen.writeUInt16BE(credentialId.length);
    const authData = Buffer.concat([rpIdHash, Buffer.from([flags]), counterBuf, Buffer.alloc(16), credIdLen, credentialId, cose]);
    const attestationObject = cbor({ fmt: "none", attStmt: {}, authData });
    return {
      id: b64url(credentialId),
      rawId: b64url(credentialId),
      type: "public-key",
      response: {
        clientDataJSON: b64url(clientData("webauthn.create", options.challenge)),
        attestationObject: b64url(attestationObject),
        transports: ["internal"]
      },
      clientExtensionResults: {},
      authenticatorAttachment: "platform"
    };
  }

  /** The response to navigator.credentials.get() for the given options. */
  function assert(options, { userVerified = true, signWith = privateKey } = {}) {
    counter += 1;
    const flags = 0x01 | (userVerified ? 0x04 : 0);
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32BE(counter);
    const authData = Buffer.concat([rpIdHash, Buffer.from([flags]), counterBuf]);
    const cd = clientData("webauthn.get", options.challenge);
    const signature = crypto.sign("sha256", Buffer.concat([authData, crypto.createHash("sha256").update(cd).digest()]), signWith);
    return {
      id: b64url(credentialId),
      rawId: b64url(credentialId),
      type: "public-key",
      response: {
        clientDataJSON: b64url(cd),
        authenticatorData: b64url(authData),
        signature: b64url(signature),
        userHandle: null
      },
      clientExtensionResults: {},
      authenticatorAttachment: "platform"
    };
  }

  return { register, assert, credentialId: b64url(credentialId), get counter() { return counter; } };
}

module.exports = { createFakeAuthenticator, cbor };
