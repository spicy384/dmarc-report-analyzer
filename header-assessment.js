/**
 * One answer on top of the header analysis: was this message more likely spoofed, or
 * sent by a server authorised to send as the From domain? ("Authorized sender" is
 * all it claims: the content can still be unwanted.) Every signal the analysis already
 * carries is given a weight, for or against, and the sum lands on a five-step scale
 * with a confidence that says how much evidence there was. It is a guess, stated with
 * its reasons, and the reasons are the product: a reader can disagree with any of them.
 *
 * What counts FOR the sender comes only from what the receiving server itself recorded
 * (the newest Authentication-Results). Everything else in a header block can be written
 * by whoever sent the message: ARC seals, Received-SPF, spam-filter stamps, older
 * Authentication-Results. Those may count against a message, never for it.
 *
 * Pure: takes the analysis object and the installation's own domains, returns the
 * assessment. Nothing is looked up here.
 */
const { domainToUnicode } = require("url");
const { organizationalDomain: orgDomain } = require("./domains");

const LEVELS = [
  { id: "likely-spoofed", label: "Likely spoofed", min: -Infinity, max: -40 },
  { id: "suspicious", label: "Suspicious", min: -39, max: -15 },
  { id: "unclear", label: "Unclear", min: -14, max: 14 },
  { id: "probably-authorized", label: "Probably authorized sender", min: 15, max: 39 },
  { id: "likely-authorized", label: "Likely authorized sender", min: 40, max: Infinity }
];

// An impersonation signal (a look-alike domain, a borrowed name, a hidden address) keeps
// the verdict at "Suspicious" or worse however well the message authenticates: the
// impersonator's own domain passing every check is the whole trick.
const IMPERSONATION_CEILING = -15;
const MAX_SIGNATURES_ASSESSED = 6;
const MAX_OWN_DOMAINS = 200;

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

/** Quoted header text in a reason: short, so a long name cannot bury the rest. */
function clip(text, max = 80) {
  const s = String(text || "");
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** An email address shown inside a display name, or null. Linear: neither side of the @ may contain one. */
function shownAddress(name) {
  const hit = String(name || "").slice(0, 320).match(/[^\s<>"@]+@[^\s<>"@]+\.[a-z]{2,}/i);
  return hit ? hit[0] : null;
}

/** The label before the public suffix, as a reader sees it: punycode decoded, compatibility forms folded. */
function brandLabel(domain) {
  const org = orgDomain(String(domain || "").toLowerCase());
  if (!org) return "";
  const shown = domainToUnicode(org) || org;
  return shown.split(".")[0].normalize("NFKC").slice(0, 63);
}

function ownedSet(ownDomains) {
  return new Set((ownDomains || []).map((d) => orgDomain(String(d).toLowerCase())).filter(Boolean));
}

/**
 * Whether `domain` is a near miss of one of `ownDomains` (and not itself one of them):
 * a look-alike character, the same name under another public suffix, or, for names of
 * six letters and more, a swapped letter or an added word. Short names only match
 * exactly, since "acne" is not an attack on "acme". Returns the domain it resembles.
 */
function lookalikeOf(domain, ownDomains) {
  const org = orgDomain(String(domain || "").toLowerCase());
  if (!org) return null;
  const owned = ownedSet(ownDomains);
  if (owned.has(org)) return null;
  const label = brandLabel(org);
  const folded = foldLookalikes(label);
  for (const own of owned) {
    const ownLabel = brandLabel(own);
    if (ownLabel.length < 4) continue;
    if (label === ownLabel) return own; // same name, another suffix: contoso.net for contoso.com
    if (folded === foldLookalikes(ownLabel)) return own;
    if (ownLabel.length < 6) continue;
    if (levenshtein(label, ownLabel) <= (ownLabel.length >= 8 ? 2 : 1)) return own;
    // contoso-billing.com, contosohelp.net, my-contoso.com
    if (label.includes(ownLabel) && label.length - ownLabel.length <= 12) return own;
  }
  return null;
}

/**
 * Your name used as a subdomain of somebody else's domain: example.com.secure-login.test,
 * or contoso.some-saas.com. Returns the own domain it borrows, or null. Tenants on
 * hosted services look exactly like this too, so it is a weaker signal than a look-alike.
 */
function subdomainBrandOf(domain, ownDomains) {
  const full = String(domain || "").toLowerCase();
  const org = orgDomain(full);
  if (!org || full === org) return null;
  const owned = ownedSet(ownDomains);
  if (owned.has(org)) return null;
  const sub = full.slice(0, full.length - org.length - 1).split(".").filter(Boolean).slice(-6);
  for (const own of owned) {
    const ownLabel = brandLabel(own);
    if (ownLabel.length < 4) continue;
    if (sub.some((l) => l === ownLabel || foldLookalikes(l) === foldLookalikes(ownLabel) || (ownLabel.length >= 6 && l.includes(ownLabel)))) return own;
  }
  return null;
}

/** Whether a display name trades on one of the installation's own brands (as a whole word, look-alike digits folded). */
function brandInName(name, ownDomains) {
  const text = String(name || "").toLowerCase().slice(0, 320);
  if (!text) return null;
  const folded = foldLookalikes(text);
  for (const own of ownDomains || []) {
    const label = brandLabel(own);
    if (label.length < 4) continue;
    const word = new RegExp(`(^|[^a-z0-9])${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![a-z0-9])`, "i");
    if (word.test(text) || word.test(folded)) return own;
  }
  return null;
}

/**
 * Which domains count as yours. An explicit list (OWN_DOMAINS) is taken as given.
 * Otherwise they are derived from the DMARC reports, with care: anyone can mail a
 * forged report to the rua address, so a domain needs several reports from more than
 * one reporter with passing mail, the biggest are taken first, and a domain that is a
 * near miss of one already accepted is never accepted (a look-alike cannot report its
 * way into being "yours"; the same name under another suffix can).
 */
function trustedOwnDomains(rows, { explicit = [] } = {}) {
  const given = [...ownedSet(explicit)];
  if (given.length) return given.slice(0, MAX_OWN_DOMAINS);
  const accepted = [];
  const candidates = (rows || [])
    .filter((r) => r && r.domain && Number(r.reports) >= 3 && Number(r.reporters) >= 2 && Number(r.passed) > 0)
    .sort((x, y) => Number(y.messages || 0) - Number(x.messages || 0));
  for (const row of candidates) {
    const org = orgDomain(String(row.domain).toLowerCase());
    if (!org || accepted.includes(org)) continue;
    const near = lookalikeOf(org, accepted);
    if (near && brandLabel(near) !== brandLabel(org)) continue;
    accepted.push(org);
    if (accepted.length >= MAX_OWN_DOMAINS) break;
  }
  return accepted;
}

function assessHeaders(analysis, { ownDomains = [] } = {}) {
  const a = analysis || {};
  const v = a.verdicts || {};
  const from = a.summary && a.summary.from;
  const fromDomain = from && from.domain ? from.domain.toLowerCase() : null;
  const fromOrg = fromDomain ? orgDomain(fromDomain) : null;
  const owned = ownedSet(ownDomains);
  const fromIsOwn = Boolean(fromOrg && owned.has(fromOrg));
  const hasAuthResults = Array.isArray(a.authResults) && a.authResults.length > 0;
  const reasons = [];
  const caveats = [];
  const add = (weight, text) => reasons.push({ effect: weight >= 0 ? "authorized" : "spoofed", weight, text });
  let thinEvidence = false;

  // --- authentication: the backbone of the answer ------------------------------------------
  const dmarc = v.dmarc || {};
  // Only what the receiver recorded counts for the sender. `dmarc.trusted` is false when the
  // result was pieced together from a Received-SPF header, which the sender could have added.
  const trustedBasis = hasAuthResults && dmarc.trusted !== false;
  const receiverFromOrg = dmarc.headerFrom ? orgDomain(String(dmarc.headerFrom).toLowerCase()) : null;
  const fromMismatch = Boolean(receiverFromOrg && fromOrg && receiverFromOrg !== fromOrg);
  const fromHeaders = Number(a.summary && a.summary.fromHeaders) || 1;
  // The receiver's own word on the ARC chain; the cv= tag of a raw ARC-Seal is the sender's to write.
  const arcValidated = Boolean(v.arc && v.arc.result === "pass");
  const receiverOverrode = dmarc.computed === "fail" && ["pass", "bestguesspass"].includes(dmarc.reported) && !fromMismatch && fromHeaders === 1;
  const forwarded = receiverOverrode;
  // What the forwarder saw before it touched the message. Believed only when the receiver
  // validated the chain and acted on it: on its own, an ARC record is a claim by whoever sealed it.
  const arcSawPass = receiverOverrode && arcValidated && fromOrg && (a.arcAuthResults || []).some((ar) => (ar.results || []).some((r) => r.method === "dmarc" && r.result === "pass" && orgDomain(String(r.props["header.from"] || "").toLowerCase()) === fromOrg));

  if (dmarc.computed === "pass" && dmarc.reported === "fail") {
    add(-35, `The receiving server recorded dmarc=fail for ${fromDomain}. A passing result elsewhere in these headers is not the receiver's own and could have been added by the sender.`);
  } else if (dmarc.computed === "pass" && !trustedBasis) {
    thinEvidence = true;
    add(10, `SPF passes for ${fromDomain} according to a Received-SPF header, but no result from the receiving server confirms it.`);
    caveats.push("The SPF result comes from a Received-SPF header rather than the receiving server's Authentication-Results; a sender can add that header, so it counts for little.");
  } else if (dmarc.computed === "pass") {
    const viaDkim = (dmarc.via || []).includes("DKIM");
    if (fromOrg && FREE_MAIL.has(fromOrg)) {
      // Anyone can open a mailbox there: a pass proves the provider sent it, not who the sender is.
      add(15, `DMARC passes for ${fromDomain}, which only shows the message really went through that public mail provider.`);
    } else {
      add(viaDkim ? 40 : 30, `DMARC passes for ${fromDomain}: ${(dmarc.via || []).join(" and ")} aligned with the From domain${viaDkim ? ", so the content was signed by that domain" : " (SPF only: the sending server is authorised, the content is not signed)"}.`);
    }
    if (dmarc.reported === "pass" && !fromMismatch) add(10, "The receiving server recorded the same DMARC pass.");
    if (fromIsOwn) add(10, `${fromOrg} is one of your own domains, and this message authenticates as it.`);
  } else if (dmarc.computed === "fail") {
    if (!hasAuthResults) thinEvidence = true;
    if (receiverOverrode) {
      add(-10, `SPF and DKIM do not align with ${fromDomain}, but the receiving server overrode the failure (dmarc=${dmarc.reported}): a forwarder or mailing list probably broke the authentication, not a forger.`);
      add(10, `The receiving server itself recorded dmarc=${dmarc.reported}${arcValidated ? ", after validating the forwarder's ARC chain" : ""}.`);
      if (arcSawPass) add(25, `Before it was forwarded, the message passed DMARC for ${fromDomain}: the ARC record the receiver accepted says so.`);
      caveats.push("Forwarded mail fails SPF and often DKIM through no fault of the sender; the verdict leans on the receiver's decision to accept it.");
    } else if (arcValidated) {
      add(-25, `DMARC fails for ${fromDomain}. The receiver validated an ARC chain, which shows an intermediary handled the message, but did not take it as proof of the original sender; anyone can seal a chain with a domain of their own.`);
    } else {
      add(-35, `DMARC fails for ${fromDomain}: neither SPF nor DKIM authenticates the From domain${dmarc.policy && dmarc.policy !== "none" ? ` (the domain asks receivers to ${dmarc.policy} such mail)` : ""}.`);
    }
    if (dmarc.policy === "none") caveats.push(`${fromDomain} publishes p=none, so receivers deliver failing mail anyway; the failure is still real.`);
  } else {
    thinEvidence = true;
    caveats.push(hasAuthResults ? "The receiving server recorded no SPF or DKIM result, so authentication could not be judged." : "No Authentication-Results header: the headers were probably copied from a mail client rather than the receiving server, so SPF, DKIM and DMARC could not be checked.");
  }
  if (fromHeaders > 1) {
    add(-40, `The message carries ${fromHeaders} From headers. Receivers and mail programs can disagree on which one is the sender, a known way to slip a forged name past the checks.`);
  } else if (fromMismatch) {
    add(-40, `The receiving server evaluated DMARC for ${clip(dmarc.headerFrom, 60)}, but the From header shown here is ${fromDomain}: the two disagree about who the message is from.`);
  }
  if (a.dmarcRecord && fromDomain && a.dmarcRecord.found === false && !a.dmarcRecord.error) {
    add(-5, `${fromDomain} publishes no DMARC record, so nothing stops anyone sending as it.`);
  }
  // Each distinct signature once (a message can repeat one to pad the count), and only the first few.
  const seenSignatures = new Set();
  let keyBonusGiven = false;
  for (const sig of a.signatures || []) {
    const name = `${clip(sig.selector || "?", 40)}._domainkey.${clip(sig.domain || "?", 60)}`;
    if (seenSignatures.has(name)) continue;
    if (seenSignatures.size >= MAX_SIGNATURES_ASSESSED) break;
    seenSignatures.add(name);
    if (sig.result && sig.result !== "pass" && !forwarded) add(-15, `The DKIM signature ${name} does not verify: the message was altered after signing, or the signature was forged.`);
    if (sig.signsFrom === false) add(-10, `The DKIM signature ${name} leaves the From header unsigned, which defeats its purpose.`);
    if (sig.bodyLength !== null && sig.bodyLength !== undefined) add(-5, `The DKIM signature ${name} signs only part of the body (l=), so text could have been appended.`);
    if (!keyBonusGiven && trustedBasis && sig.result === "pass" && sig.aligned && sig.signsFrom !== false && sig.dns && sig.dns.found) {
      keyBonusGiven = true;
      add(5, `The aligned DKIM key ${name} is still published, as a maintained sender's would be.`);
    }
  }

  // --- impersonation that authentication cannot see -------------------------------------
  let impersonation = false;
  let hiddenAddress = false;
  if (from && from.name && from.address) {
    const shown = shownAddress(from.name);
    if (shown && !from.name.toLowerCase().includes(from.address.toLowerCase())) {
      hiddenAddress = true;
      impersonation = true;
      add(-30, `The display name shows a different address ("${clip(shown)}") from the real sender ${from.address}: the classic way to disguise who a message is from.`);
    }
  }
  const lookalike = fromDomain ? lookalikeOf(fromDomain, ownDomains) : null;
  if (lookalike) {
    impersonation = true;
    add(-65, `${fromOrg} looks like your domain ${lookalike} but is not it; a near-miss domain can authenticate perfectly and still impersonate you.`);
  }
  const subBrand = !lookalike && !fromIsOwn && fromDomain ? subdomainBrandOf(fromDomain, ownDomains) : null;
  if (subBrand) add(-15, `${fromDomain} uses the name of your domain ${subBrand} as a subdomain of ${fromOrg}. Hosted services name their tenants this way, and so do phishing sites.`);
  const brand = !fromIsOwn && !lookalike && !hiddenAddress && from ? brandInName(from.name, ownDomains) : null;
  if (brand) {
    impersonation = true;
    const freeMail = Boolean(fromOrg && FREE_MAIL.has(fromOrg));
    add(freeMail ? -40 : -25, `The display name "${clip(from.name)}" uses the name of your domain ${brand}, but the message comes from ${fromDomain || "another domain"}${freeMail ? ", a public mail provider" : ""}.`);
  }

  const replyTo = a.summary && a.summary.replyTo;
  if (replyTo && replyTo.domain && fromOrg && orgDomain(replyTo.domain) !== fromOrg) {
    const replyOrg = orgDomain(replyTo.domain);
    const replyLookalike = lookalikeOf(replyTo.domain, ownDomains);
    if (replyLookalike) {
      impersonation = true;
      add(-40, `Replies go to ${clip(replyTo.address)}, on a domain that looks like yours (${replyLookalike}) but is not.`);
    } else if (FREE_MAIL.has(replyOrg) && !FREE_MAIL.has(fromOrg)) {
      add(-25, `Replies are diverted to ${clip(replyTo.address)}, a public mailbox, while the message claims to come from ${fromDomain}.`);
    } else {
      add(-15, `Replies go to ${clip(replyTo.address)}, a different domain from the From address.`);
    }
  }

  // --- the sending system ---------------------------------------------------------------
  // The address earns credit only when the receiving server named it; one read from a
  // Received-SPF header, a spam-filter stamp or the Received chain can be invented.
  const source = a.source;
  if (source && source.ip && !source.private) {
    if (source.trusted === true) {
      if (source.known && source.known.kind === "ours") add(25, `Handed over by ${source.ip}, which you labelled as yours ("${clip(source.known.label)}").`);
      else if (source.known && source.known.kind === "vendor") add(15, `Handed over by ${source.ip}, a sending service you labelled ("${clip(source.known.label)}").`);
      else if (source.known) add(5, `Handed over by ${source.ip}, which you labelled "${clip(source.known.label)}".`);
      else if (source.catalogue) add(5, `Handed over by ${source.ip}, which looks like ${source.catalogue.name} (not yet labelled).`);
    }
    const seen = source.seen;
    if (source.trusted === true && seen && seen.total >= 50 && seen.failed / seen.total <= 0.05) add(15, `${source.ip} appears in your DMARC reports with ${seen.total} messages, almost all passing.`);
    else if (seen && seen.total >= 20 && seen.failed / seen.total >= 0.5) add(-20, `${source.ip} appears in your DMARC reports with ${seen.total} messages, most of them failing.`);
    else if (!seen && fromIsOwn && !source.known && !forwarded) add(-15, `${source.ip} has never appeared in your DMARC reports, yet the message claims to be from ${fromOrg}: not one of your known sending systems.`);
  }

  // --- what the receiver's filter thought ---------------------------------------------------
  // Good marks count only when the receiver is Microsoft 365 itself (its Authentication-Results
  // carries compauth); bad marks always count, since nobody forges those against themselves.
  const m = a.microsoft;
  if (m) {
    const ours = m.trusted === true;
    if (ours && m.compauth && /^(pass|softpass)$/.test(m.compauth.result)) add(10, "Microsoft's composite authentication passed.");
    else if (m.compauth && m.compauth.result === "fail") add(-20, `Microsoft's composite authentication failed${m.compauth.meaning ? ` (${m.compauth.meaning})` : ""}.`);
    if (m.cat && ["SPOOF", "PHSH", "HPHSH", "HPHISH", "PHISH"].includes(m.cat)) add(-40, `Microsoft 365 classified the message as ${m.catMeaning || m.cat}.`);
    else if (m.cat && ["SPM", "HSPM", "MALW", "HMALW"].includes(m.cat)) add(-15, `Microsoft 365 classified the message as ${m.catMeaning || m.cat}.`);
    else if (ours && m.cat === "NONE" && m.scl !== null && m.scl <= 1) add(5, "Microsoft 365's filter found nothing wrong with it.");
    if (m.scl !== null && m.scl >= 9) add(-25, `Spam confidence level ${m.scl}: the filter was certain.`);
    else if (m.scl !== null && m.scl >= 5) add(-15, `Spam confidence level ${m.scl}.`);
  }
  for (const marker of a.otherFilters || []) {
    if (/^X-Spam-(Status|Flag)$/i.test(marker.name) && /^yes/i.test(String(marker.value || ""))) add(-15, `${marker.name} says the filter marked it as spam.`);
  }

  // --- the path ------------------------------------------------------------------------------
  if (a.transit && a.transit.totalSeconds !== null && a.transit.totalSeconds < 0) add(-10, "The hop timestamps run backwards overall: a forged or mangled Received chain, or a badly wrong clock.");

  // --- sum, scale, confidence ------------------------------------------------------------------
  let score = reasons.reduce((sum, r) => sum + r.weight, 0);
  if (impersonation && score > IMPERSONATION_CEILING) {
    score = IMPERSONATION_CEILING;
    caveats.push("An impersonation signal keeps the verdict at Suspicious however well the message authenticates: an impersonator's own domain passing every check is how the trick works.");
  }
  if (!owned.size) caveats.push("No domain is established as yours yet (too few DMARC reports, and OWN_DOMAINS is not set), so the look-alike and borrowed-name checks did not run.");
  const evidence = reasons.reduce((sum, r) => sum + Math.abs(r.weight), 0);
  let confidence = evidence >= 80 ? "high" : evidence >= 40 ? "medium" : "low";
  if (!dmarc.computed || thinEvidence) confidence = "low";
  // Without the receiver's own authentication result the strongest verdicts are out of reach either way.
  const effective = confidence === "low" ? Math.max(-39, Math.min(39, score)) : score;
  const level = LEVELS.find((l) => effective >= l.min && effective <= l.max) || LEVELS[2];
  reasons.sort((x, y) => Math.abs(y.weight) - Math.abs(x.weight));

  const top = reasons.slice(0, 3).map((r) => r.text.replace(/\.$/, ""));
  const summary = level.id === "unclear"
    ? (reasons.length ? `The signals point both ways${top.length ? `: ${top.join("; ")}` : ""}.` : "Too little in these headers to say either way.")
    : `${confidence === "low" ? "On thin evidence: " : ""}${top.join("; ")}.`;

  return { level: level.id, label: level.label, score, confidence, summary, reasons, caveats };
}

module.exports = { assessHeaders, lookalikeOf, subdomainBrandOf, brandInName, trustedOwnDomains, shownAddress, levenshtein, LEVELS, FREE_MAIL };
