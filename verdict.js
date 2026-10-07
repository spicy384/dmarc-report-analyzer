/**
 * One-line verdicts for a sending source: why its mail fails DMARC and what
 * would fix it. Works from the per-source aggregates db.ips() already computes
 * (aligned vs raw SPF/DKIM passes, the domains involved, the sender label) and
 * the sender catalogue's hints, so it needs no extra queries.
 *
 * Every verdict has a `code` the UI can colour by, a `headline` short enough for
 * a table cell, a `detail` sentence or two, and an `action` (or null when there
 * is nothing to do).
 */

const { organizationalDomain: orgDomain } = require("./domains");

function aligned(domain, headerFroms) {
  const org = orgDomain(domain);
  return Boolean(org) && (headerFroms || []).some((h) => orgDomain(h) === org);
}

function list(items, max = 3) {
  const uniq = [...new Set((items || []).filter(Boolean))];
  return uniq.length <= max ? uniq.join(", ") : `${uniq.slice(0, max).join(", ")} and ${uniq.length - max} more`;
}

function n(value) {
  return Number(value) || 0;
}

/**
 * @param src an ips() row: total, failed, likelyForwards, spfPassed, dkimPassed,
 *   spfRawPass, dkimRawPass, dkimSigned, headerFroms, spfDomains, dkimDomains,
 *   envelopeFroms, sender ({ kind, label } | null), catalogue ({ name, spfInclude, dkimHint } | null)
 */
function sourceVerdict(src) {
  const total = n(src.total);
  const failed = n(src.failed);
  const forwards = Math.min(failed, n(src.likelyForwards));
  const realFailed = failed - forwards;
  const spfAligned = n(src.spfPassed);
  const dkimAligned = n(src.dkimPassed);
  const spfRaw = n(src.spfRawPass);
  const dkimRaw = n(src.dkimRawPass);
  const dkimSigned = n(src.dkimSigned);
  const headerFroms = src.headerFroms || [];
  const provider = src.catalogue ? src.catalogue.name : null;
  const who = src.sender ? src.sender.label : provider ? provider : null;
  const yours = src.sender ? src.sender.kind === "ours" || src.sender.kind === "vendor" : false;

  const foreignSpf = (src.spfDomains || []).filter((d) => !aligned(d, headerFroms));
  const foreignDkim = (src.dkimDomains || []).filter((d) => !aligned(d, headerFroms));

  const dkimFix = () => {
    const hint = src.catalogue && src.catalogue.dkimHint ? ` ${src.catalogue.dkimHint}` : "";
    if (dkimSigned === 0) {
      return `Turn on DKIM signing for ${list(headerFroms) || "your domain"}${who ? ` at ${who}` : ""}.${hint}`;
    }
    if (dkimRaw > dkimAligned && foreignDkim.length) {
      return `DKIM is signed by ${list(foreignDkim)}, not your domain, so it does not align. Set up custom DKIM for ${list(headerFroms) || "your domain"}${who ? ` at ${who}` : ""}.${hint}`;
    }
    return `Fix the DKIM signature for ${list(headerFroms) || "your domain"}: the signature is present but does not verify (wrong key in DNS, or the message is modified after signing).`;
  };

  if (total === 0) {
    return { code: "none", headline: "No messages", detail: "Nothing from this source in the period.", action: null };
  }
  if (failed === 0) {
    return { code: "pass", headline: "Passing", detail: "Every message from this source passed DMARC.", action: null };
  }
  if (realFailed === 0) {
    return {
      code: "forward",
      headline: "Forwards only",
      detail: "Every failure looks like forwarded or mailing-list mail: the reporter said so, or your DKIM signature was present but broken in transit.",
      action: "Nothing to fix on your side; these fail under any policy."
    };
  }

  // SPF passes, but for the sending service's own domain: the classic ESP case.
  if (spfRaw > spfAligned && dkimAligned < realFailed) {
    return {
      code: "unaligned",
      headline: `SPF unaligned${who ? ` (${who})` : ""}`,
      detail: `SPF passes for ${list(foreignSpf) || "the sending service's domain"}, not for ${list(headerFroms) || "your domain"}, so it does not count.${dkimSigned === 0 ? " There is no DKIM signature to fall back on." : dkimRaw > dkimAligned ? ` DKIM is signed by ${list(foreignDkim) || "another domain"}.` : ""}`,
      action: dkimFix()
    };
  }

  // No SPF pass at all.
  if (spfRaw === 0 && dkimAligned === 0) {
    if (dkimRaw > 0) {
      return {
        code: "unaligned",
        headline: `DKIM unaligned${who ? ` (${who})` : ""}`,
        detail: `Not in SPF, and DKIM is signed by ${list(foreignDkim) || "another domain"} rather than ${list(headerFroms) || "your domain"}.`,
        action: dkimFix()
      };
    }
    if (yours) {
      return {
        code: "unauthorised",
        headline: `Not authorised (${who})`,
        detail: `You labelled this ${src.sender.kind === "ours" ? "as yours" : "as a vendor"}, but nothing vouches for it: it is not in SPF for ${list(headerFroms) || "your domain"} and sends no DKIM signature.`,
        action: `${src.catalogue && src.catalogue.spfInclude ? `Add ${src.catalogue.spfInclude} to your SPF record` : "Add it to your SPF record (an include for the service, or its IPs)"} and ${dkimSigned === 0 ? "turn on DKIM signing" : "fix DKIM"} for ${list(headerFroms) || "your domain"}.`
      };
    }
    return {
      code: "spoof",
      headline: provider ? `Unauthorised (${provider})` : "Nothing vouches for it",
      detail: `Not in SPF for ${list(headerFroms) || "your domain"} and no DKIM signature.${provider ? ` The address belongs to ${provider}, which anyone can use.` : ""} If this is not a service you use, it is spoofing and a reject policy is the right answer.`,
      action: `If it is yours, label it and ${src.catalogue && src.catalogue.spfInclude ? `add ${src.catalogue.spfInclude} to SPF` : "add it to SPF"} or set up DKIM. Otherwise nothing to do.`
    };
  }

  // Some messages align and some do not: usually broken signatures or a subset of streams.
  if (spfAligned + dkimAligned > 0) {
    const brokenDkim = dkimSigned > dkimRaw;
    return {
      code: "partial",
      headline: `Partly failing${who ? ` (${who})` : ""}`,
      detail: `${realFailed} of ${total} messages failed while others from the same source pass.${brokenDkim ? " Some DKIM signatures are present but do not verify." : ""}${spfRaw > spfAligned ? ` Some SPF passes are for ${list(foreignSpf)}, which does not align.` : ""}`,
      action: brokenDkim
        ? "Check the DKIM key in DNS matches the selector in use, and look for rules that modify messages (footers, disclaimers) after signing."
        : "Open the records to see which stream fails; it is usually one application or one sending domain behind the same server."
    };
  }

  return {
    code: "mixed",
    headline: `Failing${who ? ` (${who})` : ""}`,
    detail: `${realFailed} of ${total} messages failed DMARC for ${list(headerFroms) || "your domain"}.`,
    action: "Open the records for the SPF and DKIM results per report."
  };
}

module.exports = { sourceVerdict, orgDomain };
