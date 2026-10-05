/**
 * Node's fetch reports every network failure as "fetch failed" and hides the
 * reason in error.cause. This turns it into something a person can act on:
 * the low-level code, the host it concerned, and what that usually means.
 */
const HINTS = {
  ENOTFOUND: "the host name did not resolve; check the DNS servers this host or container uses",
  EAI_AGAIN: "DNS did not answer in time; the resolver is unreachable or overloaded",
  ECONNREFUSED: "the connection was refused; a firewall or proxy is rejecting it",
  ECONNRESET: "the connection was cut mid-way; often a firewall, proxy or TLS inspection device",
  ETIMEDOUT: "the connection timed out; outbound HTTPS (port 443) is probably blocked",
  EHOSTUNREACH: "no route to the host; check the network or default gateway",
  ENETUNREACH: "the network is unreachable; often IPv6 without a working route, or no default gateway",
  UND_ERR_CONNECT_TIMEOUT: "the connection timed out; outbound HTTPS (port 443) is probably blocked",
  UND_ERR_SOCKET: "the connection closed unexpectedly; often a proxy or TLS inspection device",
  UND_ERR_HEADERS_TIMEOUT: "the server accepted the connection but never answered",
  CERT_HAS_EXPIRED: "the certificate presented is expired; check the host's clock, or a TLS inspection proxy",
  DEPTH_ZERO_SELF_SIGNED_CERT: "a self-signed certificate was presented; a TLS inspection proxy is in the path",
  SELF_SIGNED_CERT_IN_CHAIN: "the chain contains a private root; a TLS inspection proxy is in the path (set NODE_EXTRA_CA_CERTS to its root)",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: "the certificate chain could not be verified; a TLS inspection proxy is in the path (set NODE_EXTRA_CA_CERTS to its root)",
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "the issuing certificate is not trusted here; a TLS inspection proxy is in the path (set NODE_EXTRA_CA_CERTS to its root)",
  ERR_TLS_CERT_ALTNAME_INVALID: "the certificate is for a different host name; something is intercepting the connection"
};

function describeFetchError(error) {
  if (!error) return "unknown error";
  if (error.name === "AbortError" || error.name === "TimeoutError") return "the request timed out";
  // undici nests causes; an AggregateError holds one per address tried.
  let cause = error.cause || null;
  if (cause && Array.isArray(cause.errors) && cause.errors.length) cause = cause.errors[0];
  const code = (cause && cause.code) || error.code || null;
  if (!code && !cause) return error.message;
  const host = cause && (cause.hostname || cause.host || cause.address) ? ` ${cause.hostname || cause.host || cause.address}` : "";
  const hint = HINTS[code];
  const detail = cause && cause.message && cause.message !== error.message ? cause.message : "";
  return `${error.message} (${[code ? `${code}${host}` : null, hint || detail || null].filter(Boolean).join(": ")})`;
}

module.exports = { describeFetchError, HINTS };
