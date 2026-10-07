/**
 * The organisational (registrable) domain of a name, which DMARC uses for the
 * record fallback and for relaxed alignment: mail.example.com -> example.com, but
 * news.example.co.uk -> example.co.uk, not co.uk. Backed by the public suffix
 * list that ships with tldts (offline). Names the list knows nothing about (a
 * bare host, an internal domain) fall back to their last two labels.
 */
const { getDomain } = require("tldts");

function organizationalDomain(domain) {
  const d = String(domain || "").trim().toLowerCase().replace(/\.$/, "");
  if (!d) return "";
  const known = getDomain(d, { allowPrivateDomains: false });
  if (known) return known;
  const labels = d.split(".").filter(Boolean);
  return labels.length <= 2 ? labels.join(".") : labels.slice(-2).join(".");
}

module.exports = { organizationalDomain };
