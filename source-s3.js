/**
 * Amazon SES source. SES does not hold mail: inbound receiving delivers each
 * message to an S3 bucket through a receipt rule (action "Deliver to S3
 * bucket"), one raw RFC 822 object per message. This source reads those
 * objects: ListObjectsV2 under a prefix, then GetObject per new message.
 *
 * No AWS SDK: requests are signed with Signature Version 4 using Node's crypto.
 * An `endpoint` override (path-style) makes S3-compatible stores and tests work.
 */
const crypto = require("crypto");
const { XMLParser } = require("fast-xml-parser");
const { createRawSource, SourceError } = require("./source-raw");

const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

function sha256Hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function hmac(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest();
}

/** RFC 3986 encoding as SigV4 wants it; `/` is kept in paths only. */
function encodeRfc3986(text, keepSlash = false) {
  const encoded = encodeURIComponent(text).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return keepSlash ? encoded.replace(/%2F/g, "/") : encoded;
}

/**
 * Signs a request with AWS Signature Version 4 and returns the headers to send
 * (the ones passed in, plus host, x-amz-date, x-amz-content-sha256 and Authorization).
 */
function signV4({ method = "GET", url, headers = {}, region, service = "s3", accessKeyId, secretAccessKey, sessionToken, payloadHash = EMPTY_SHA256, now = new Date() }) {
  const u = new URL(url);
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  const dateStamp = amzDate.slice(0, 8);

  const all = { ...headers, host: u.host, "x-amz-content-sha256": payloadHash, "x-amz-date": amzDate };
  if (sessionToken) all["x-amz-security-token"] = sessionToken;
  const canonicalHeaderNames = Object.keys(all).map((k) => k.toLowerCase()).sort();
  const lowered = Object.fromEntries(Object.entries(all).map(([k, v]) => [k.toLowerCase(), String(v).trim().replace(/\s+/g, " ")]));
  const canonicalHeaders = canonicalHeaderNames.map((k) => `${k}:${lowered[k]}\n`).join("");
  const signedHeaders = canonicalHeaderNames.join(";");

  const query = [...u.searchParams.entries()]
    .map(([k, v]) => [encodeRfc3986(k), encodeRfc3986(v)])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
  const canonicalPath = u.pathname.split("/").map((seg) => encodeRfc3986(decodeURIComponent(seg))).join("/") || "/";

  const canonicalRequest = [method, canonicalPath, query, canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonicalRequest)].join("\n");
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${secretAccessKey}`, dateStamp), region), service), "aws4_request");
  const signature = crypto.createHmac("sha256", signingKey).update(stringToSign).digest("hex");

  return {
    ...all,
    Authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    signature
  };
}

/**
 * @param cfg { region, bucket, prefix, accessKeyId, secretAccessKey, sessionToken, endpoint }
 */
function createS3Source(cfg, { idPrefix = "ses:", fetchImpl = globalThis.fetch, now = () => new Date() } = {}) {
  const config = { prefix: "", ...cfg };
  const xml = new XMLParser({ ignoreAttributes: true, parseTagValue: false, isArray: (name) => name === "Contents" });

  const isConfigured = () => Boolean(config.region && config.bucket && config.accessKeyId && config.secretAccessKey);
  const missing = () => [!config.region && "region", !config.bucket && "bucket", !config.accessKeyId && "access key ID", !config.secretAccessKey && "secret access key"].filter(Boolean);

  /** Virtual-hosted style against AWS; path style against a custom endpoint. */
  function objectUrl(key, query = "") {
    const encodedKey = key ? key.split("/").map((seg) => encodeRfc3986(seg)).join("/") : "";
    const base = config.endpoint
      ? `${String(config.endpoint).replace(/\/+$/, "")}/${config.bucket}/${encodedKey}`
      : `https://${config.bucket}.s3.${config.region}.amazonaws.com/${encodedKey}`;
    return query ? `${base}?${query}` : base;
  }

  async function request(url, stage) {
    const { signature, ...headers } = signV4({ url, region: config.region, accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey, sessionToken: config.sessionToken, now: now() });
    delete headers.host; // fetch sets it
    let res;
    try {
      res = await fetchImpl(url, { headers });
    } catch (error) {
      throw new SourceError(`Could not reach S3 (${config.bucket} in ${config.region}): ${error.message}`, { code: "network", fatal: true, stage: "connection" });
    }
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      const code = (body.match(/<Code>([^<]+)<\/Code>/) || [])[1] || `HTTP ${res.status}`;
      const message = (body.match(/<Message>([^<]+)<\/Message>/) || [])[1] || "";
      const hints = {
        AccessDenied: " The access key needs s3:ListBucket on the bucket and s3:GetObject on its objects.",
        InvalidAccessKeyId: " Check the access key ID.",
        SignatureDoesNotMatch: " Check the secret access key.",
        NoSuchBucket: " Check the bucket name and region.",
        PermanentRedirect: " The bucket is in a different region than the one configured.",
        AuthorizationHeaderMalformed: " The bucket is in a different region than the one configured."
      };
      const fatal = res.status !== 404 || code === "NoSuchBucket";
      throw new SourceError(`S3 ${code}${message ? `: ${message}` : ""}.${hints[code] || ""}`, { code: code === "NoSuchKey" ? "gone" : "s3", fatal, stage: res.status === 403 ? "login" : stage });
    }
    return res;
  }

  async function listPage(continuationToken, maxKeys = 1000) {
    const params = new URLSearchParams({ "list-type": "2", "max-keys": String(maxKeys) });
    if (config.prefix) params.set("prefix", config.prefix);
    if (continuationToken) params.set("continuation-token", continuationToken);
    const res = await request(objectUrl("", params.toString()), "list");
    const parsed = xml.parse(await res.text());
    const result = parsed.ListBucketResult || {};
    return {
      objects: (result.Contents || []).map((c) => ({ key: String(c.Key), lastModified: Math.floor(Date.parse(c.LastModified) / 1000), size: Number(c.Size) || 0 })),
      next: String(result.IsTruncated) === "true" ? result.NextContinuationToken : null,
      count: Number(result.KeyCount) || 0
    };
  }

  async function open() {
    if (!isConfigured()) {
      throw new SourceError(`Amazon SES (S3) is not configured: missing ${missing().join(", ")}.`, { code: "not_configured", fatal: true, stage: "config" });
    }
    return {
      async *list({ since }) {
        let token = null;
        const found = [];
        do {
          const page = await listPage(token);
          for (const o of page.objects) {
            // Folder placeholders and the file SES writes when the rule is created are not messages.
            if (o.size === 0 || o.key.endsWith("/") || /AMAZON_SES_SETUP_NOTIFICATION$/.test(o.key)) continue;
            if (since && o.lastModified < since) continue;
            found.push(o);
          }
          token = page.next;
        } while (token);
        for (const o of found.sort((a, b) => a.lastModified - b.lastModified)) {
          yield { key: o.key, receivedAt: o.lastModified };
        }
      },
      async fetchRaw(key) {
        const res = await request(objectUrl(key), "fetch");
        return Buffer.from(await res.arrayBuffer());
      },
      async close() {}
    };
  }

  async function test() {
    const page = await listPage(null, 5);
    return `Listed s3://${config.bucket}/${config.prefix || ""} in ${config.region}: ${page.objects.length ? `${page.objects.length}${page.next ? "+" : ""} object${page.objects.length === 1 ? "" : "s"} visible` : "no objects yet"}.`;
  }

  return createRawSource({
    type: "ses",
    // The bucket is part of the id so two mailboxes on different buckets never collide.
    idPrefix,
    config,
    isConfigured,
    missing,
    describe: () => ({ region: config.region, bucket: config.bucket, prefix: config.prefix || "", accessKeyId: config.accessKeyId, endpoint: config.endpoint || null }),
    authMethod: () => "access key",
    open,
    test
  });
}

module.exports = { createS3Source, signV4, encodeRfc3986 };
