/**
 * One answer on top of the header analysis: is this message more likely spoofed or
 * sent from a legitimate source? Every signal the analysis already carries is given
 * a weight, for or against, and the sum lands on a five-step scale with a confidence
 * that says how much evidence there was. It is a guess, stated with its reasons, and
 * the reasons are the product: a reader can disagree with any of them.
 *
 * Pure: takes the analysis object and the installation's own domains (from the
 * DMARC reports), returns the assessment. Nothing is looked up here.
 */
const { organizationalDomain: orgDomain } = require("./domains");

const LEVELS = [
  { id: "likely-spoofed", label: "Likely spoofed", min: -Infinity, max: -40 },
  { id: "suspicious", label: "Suspicious", min: -39, max: -15 },
  { id: "unclear", label: "Unclear", min: -14, max: 14 },
  { id: "probably-legitimate", label: "Probably legitimate", min: 15, max: 39 },
  { id: "likely-legitimate", label: "Likely legitimate", min: 40, max: Infinity }
];

// Public mailbox providers: a business sender on one of these is not itself suspicious,
// but a Reply-To that moves the conversation there is a classic diversion.
const FREE_MAIL = new Set(["gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "gmx.com", "gmx.de", "gmx.net", "mail.com", "yandex.com", "yandex.ru", "zoho.com", "fastmail.com", "mail.ru", "qq.com", "163.com"]);

// Letters an attacker swaps for look-alikes, folded before comparing domain labels.
const HOMOGLYPHS = { 0: "o", 1: "l", 3: "e", 4: "a", 5: "s", 7: "t", 8: "b", "|": "l", "rn": "m", "vv": "w" };

function foldLookalikes(label) {
  let out = String(label || "").toLowerCase();
  for (const [from, to] of Object.entries(HOMOGLYPHS)) out = out.split(from).join(to);
  return out;
}

/** Edit distance, for near-miss labels. */
function levenshtein(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    const cur = [i];
    for (let j = 1; j <= b.length; j += 1) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length];
}

/** The part of an organisational domain before the public suffix: "contoso" for contoso.co.uk. */
function brandLabel(domain) {
  const org = orgDomain(String(domain || "").toLowerCase());
  return org ? org.split(".")[0] : "";
}

/**
 * Whether `domain` is a near miss of one of `ownDomains` (and not itself one of them):
 * a swapped letter, a look-alike character, an added word, or the same name under
 * another public suffix. Returns the domain it resembles, or null.
 */
function lookalikeOf(domain, ownDomains) {
  const org = orgDomain(String(domain || "").toLowerCase());
  if (!org) return null;
  const owned = new Set((ownDomains || []).map((d) => orgDomain(String(d).toLowerCase())).filter(Boolean));
  if (owned.has(org)) return null;
  const label = org.split(".")[0];
  const folded = foldLookalikes(label);
  for (const own of owned) {
    const ownLabel = own.split(".")[0];
    if (ownLabel.length < 4) continue;
    if (label === ownLabel) return own; // same name, another suffix: contoso.net for contoso.com
    if (folded === foldLookalikes(ownLabel)) return own;
    const distance = levenshtein(label, ownLabel);
    if (distance <= (ownLabel.length >= 8 ? 2 : 1)) return own;
    // contoso-billing.com, contosohelp.net, my-contoso.com
    if (label.includes(ownLabel) && label.length - ownLabel.length <= 12) return own;
  }
  return null;
}

/** Whether a display name trades on one of the installation's own brands. */
function brandInName(name, ownDomains) {
  const text = String(name || "").toLowerCase();
  if (!text) return null;
  for (const own of ownDomains || []) {
    const label = brandLabel(own);
    if (label.length >= 4 && new RegExp(`(^|[^a-z0-9])${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`, "i").test(text)) return own;
  }
  return null;
}

function assessHeaders(analysis, { ownDomains = [] } = {}) {
  const a = analysis || {};
  const v = a.verdicts || {};
  const from = a.summary && a.summary.from;
  const fromDomain = from && from.domain ? from.domain.toLowerCase() : null;
  const fromOrg = fromDomain ? orgDomain(fromDomain) : null;
  const owned = new Set(ownDomains.map((d) => orgDomain(String(d).toLowerCase())).filter(Boolean));
  const fromIsOwn = Boolean(fromOrg && owned.has(fromOrg));
  const hasAuthResults = Array.isArray(a.authResults) && a.authResults.length > 0;
  const reasons = [];
  const caveats = [];
  const add = (weight, text) => reasons.push({ effect: weight >= 0 ? "legitimate" : "spoofed", weight, text });

  // --- authentication: the backbone of the answer ------------------------------------------
  const dmarc = v.dmarc || {};
  const arcPass = Boolean(v.arc && (v.arc.chain === "pass" || v.arc.result === "pass"));
  const receiverOverrode = ["pass", "bestguesspass"].includes(dmarc.reported) && dmarc.computed === "fail";
  const forwarded = dmarc.computed === "fail" && (arcPass || receiverOverrode);
  // What the forwarder saw before it touched the message, from ARC-Authentication-Results.
  const arcSawPass = forwarded && fromOrg && (a.arcAuthResults || []).some((ar) => (ar.results || []).some((r) => r.method === "dmarc" && r.result === "pass" && orgDomain(String(r.props["header.from"] || "").toLowerCase()) === fromOrg));
  if (dmarc.computed === "pass") {
    const viaDkim = (dmarc.via || []).includes("DKIM");
    if (fromOrg && FREE_MAIL.has(fromOrg)) {
      // Anyone can open a mailbox there: a pass proves the provider sent it, not who the sender is.
      add(15, `DMARC passes for ${fromDomain}, which only shows the message really went through that public mail provider.`);
    } else {
      add(viaDkim ? 40 : 30, `DMARC passes for ${fromDomain}: ${(dmarc.via || []).join(" and ")} aligned with the From domain${viaDkim ? ", so the content was signed by that domain" : " (SPF only: the sending server is authorised, the content is not signed)"}.`);
    }
    if (dmarc.reported === "pass") add(10, "The receiving server recorded the same DMARC pass.");
    if (fromIsOwn) add(10, `${fromOrg} is one of your own domains, and this message authenticates as it.`);
  } else if (dmarc.computed === "fail") {
    if (arcPass || receiverOverrode) {
      add(-10, `SPF and DKIM do not align with ${fromDomain}, but ${arcPass ? "an ARC chain shows the message was forwarded intact" : `the receiver overrode the failure (dmarc=${dmarc.reported})`}: a forwarder or mailing list probably broke the authentication, not a forger.`);
      if (arcSawPass) add(25, `Before it was forwarded, the message passed DMARC for ${fromDomain}: the forwarder's ARC record says so.`);
      if (receiverOverrode) add(10, `The receiving server itself recorded dmarc=${dmarc.reported}, accepting the forwarder's word.`);
      caveats.push("Forwarded mail fails SPF and often DKIM through no fault of the sender; the verdict leans on the other signals.");
    } else {
      add(-35, `DMARC fails for ${fromDomain}: neither SPF nor DKIM authenticates the From domain${dmarc.policy && dmarc.policy !== "none" ? ` (the domain asks receivers to ${dmarc.policy} such mail)` : ""}.`);
    }
    if (dmarc.policy === "none") caveats.push(`${fromDomain} publishes p=none, so receivers deliver failing mail anyway; the failure is still real.`);
  } else {
    caveats.push(hasAuthResults ? "The receiving server recorded no SPF or DKIM result, so authentication could not be judged." : "No Authentication-Results header: the headers were probably copied from a mail client rather than the receiving server, so SPF, DKIM and DMARC could not be checked.");
  }
  if (a.dmarcRecord && fromDomain && a.dmarcRecord.found === false && !a.dmarcRecord.error) {
    add(-5, `${fromDomain} publishes no DMARC record, so nothing stops anyone sending as it.`);
  }
  for (const sig of a.signatures || []) {
    const name = `${sig.selector || "?"}._domainkey.${sig.domain || "?"}`;
    if (sig.result && sig.result !== "pass" && !forwarded) add(-15, `The DKIM signature ${name} does not verify: the message was altered after signing, or the signature was forged.`);
    if (sig.signsFrom === false) add(-10, `The DKIM signature ${name} leaves the From header unsigned, which defeats its purpose.`);
    if (sig.bodyLength !== null && sig.bodyLength !== undefined) add(-5, `The DKIM signature ${name} signs only part of the body (l=), so text could have been appended.`);
    if (sig.result === "pass" && sig.aligned && sig.signsFrom !== false && sig.dns && sig.dns.found) add(5, `The aligned DKIM key ${name} is still published, as a maintained sender's would be.`);
  }

  // --- impersonation that authentication cannot see -------------------------------------
  let hiddenAddress = false;
  if (from && from.name && from.address) {
    const shown = from.name.match(/[^\s<>"]+@[^\s<>"]+\.[a-z]{2,}/i);
    if (shown && !from.name.toLowerCase().includes(from.address.toLowerCase())) {
      hiddenAddress = true;
      add(-30, `The display name shows a different address ("${shown[0]}") from the real sender ${from.address}: the classic way to disguise who a message is from.`);
    }
  }
  const lookalike = fromDomain ? lookalikeOf(fromDomain, ownDomains) : null;
  // Both outweigh a clean DMARC pass on purpose: a look-alike domain, or a public mailbox
  // with your name on it, authenticates perfectly and is still an impersonation.
  if (lookalike) add(-65, `${fromOrg} looks like your domain ${lookalike} but is not it; a near-miss domain can authenticate perfectly and still impersonate you.`);
  const brand = !fromIsOwn && !lookalike && !hiddenAddress && from ? brandInName(from.name, ownDomains) : null;
  if (brand) add(fromOrg && FREE_MAIL.has(fromOrg) ? -40 : -25, `The display name "${from.name}" uses the name of your domain ${brand}, but the message comes from ${fromDomain || "another domain"}${fromOrg && FREE_MAIL.has(fromOrg) ? ", a public mail provider" : ""}.`);

  const replyTo = a.summary && a.summary.replyTo;
  if (replyTo && replyTo.domain && fromOrg && orgDomain(replyTo.domain) !== fromOrg) {
    const free = FREE_MAIL.has(orgDomain(replyTo.domain));
    const fromFree = FREE_MAIL.has(fromOrg);
    if (free && !fromFree) add(-25, `Replies are diverted to ${replyTo.address}, a public mailbox, while the message claims to come from ${fromDomain}.`);
    else add(-15, `Replies go to ${replyTo.address}, a different domain from the From address.`);
  }

  // --- the sending system ---------------------------------------------------------------
  const source = a.source;
  if (source && source.ip && !source.private) {
    if (source.known && source.known.kind === "ours") add(25, `Handed over by ${source.ip}, which you labelled as yours ("${source.known.label}").`);
    else if (source.known && source.known.kind === "vendor") add(15, `Handed over by ${source.ip}, a sending service you labelled ("${source.known.label}").`);
    else if (source.known) add(5, `Handed over by ${source.ip}, which you labelled "${source.known.label}".`);
    else if (source.catalogue) add(5, `Handed over by ${source.ip}, which looks like ${source.catalogue.name} (not yet labelled).`);
    const seen = source.seen;
    if (seen && seen.total >= 50 && seen.failed / seen.total <= 0.05) add(15, `${source.ip} appears in your DMARC reports with ${seen.total} messages, almost all passing.`);
    else if (seen && seen.total >= 20 && seen.failed / seen.total >= 0.5) add(-20, `${source.ip} appears in your DMARC reports with ${seen.total} messages, most of them failing.`);
    else if (!seen && fromIsOwn && !source.known && !forwarded) add(-15, `${source.ip} has never appeared in your DMARC reports, yet the message claims to be from ${fromOrg}: not one of your known sending systems.`);
  }

  // --- what the receiver's filter thought ---------------------------------------------------
  const m = a.microsoft;
  if (m) {
    if (m.compauth && /^pass|softpass$/.test(m.compauth.result)) add(10, "Microsoft's composite authentication passed.");
    else if (m.compauth && m.compauth.result === "fail") add(-20, `Microsoft's composite authentication failed${m.compauth.meaning ? ` (${m.compauth.meaning})` : ""}.`);
    if (m.cat && ["SPOOF", "PHSH", "HPHSH", "HPHISH", "PHISH"].includes(m.cat)) add(-40, `Microsoft 365 classified the message as ${m.catMeaning || m.cat}.`);
    else if (m.cat && ["SPM", "HSPM", "MALW", "HMALW"].includes(m.cat)) add(-15, `Microsoft 365 classified the message as ${m.catMeaning || m.cat}.`);
    else if (m.cat === "NONE" && m.scl !== null && m.scl <= 1) add(5, "Microsoft 365's filter found nothing wrong with it.");
    if (m.scl !== null && m.scl >= 9) add(-25, `Spam confidence level ${m.scl}: the filter was certain.`);
    else if (m.scl !== null && m.scl >= 5) add(-15, `Spam confidence level ${m.scl}.`);
  }
  for (const marker of a.otherFilters || []) {
    if (/^X-Spam-(Status|Flag)$/i.test(marker.name) && /^yes/i.test(String(marker.value || ""))) add(-15, `${marker.name} says the filter marked it as spam.`);
  }

  // --- the path ------------------------------------------------------------------------------
  if (a.transit && a.transit.totalSeconds !== null && a.transit.totalSeconds < 0) add(-10, "The hop timestamps run backwards overall: a forged or mangled Received chain, or a badly wrong clock.");

  // --- sum, scale, confidence ------------------------------------------------------------------
  const score = reasons.reduce((sum, r) => sum + r.weight, 0);
  const evidence = reasons.reduce((sum, r) => sum + Math.abs(r.weight), 0);
  let confidence = evidence >= 80 ? "high" : evidence >= 40 ? "medium" : "low";
  if (!dmarc.computed) confidence = "low";
  // Without an authentication result the strongest verdicts are out of reach either way.
  const effective = confidence === "low" ? Math.max(-39, Math.min(39, score)) : score;
  const level = LEVELS.find((l) => effective >= l.min && effective <= l.max) || LEVELS[2];
  reasons.sort((x, y) => Math.abs(y.weight) - Math.abs(x.weight));

  const top = reasons.slice(0, 3).map((r) => r.text.replace(/\.$/, ""));
  const summary = level.id === "unclear"
    ? (reasons.length ? `The signals point both ways${top.length ? `: ${top.join("; ")}` : ""}.` : "Too little in these headers to say either way.")
    : `${confidence === "low" ? "On thin evidence: " : ""}${top.join("; ")}.`;

  return { level: level.id, label: level.label, score, confidence, summary, reasons, caveats };
}

module.exports = { assessHeaders, lookalikeOf, brandInName, levenshtein, LEVELS, FREE_MAIL };
