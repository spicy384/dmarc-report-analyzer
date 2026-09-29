/** Source verdicts and the sender catalogue: the sentence each failing pattern gets. */
const { createChecker } = require("./helpers/assert");
const { sourceVerdict, orgDomain } = require("../verdict");
const { matchCatalogue, CATALOGUE } = require("../sender-catalogue");

const { check, report } = createChecker("verdict: why a source fails, sender catalogue");

const base = {
  total: 100, failed: 100, likelyForwards: 0, spfPassed: 0, dkimPassed: 0,
  spfRawPass: 0, dkimRawPass: 0, dkimSigned: 0,
  headerFroms: ["example.com"], spfDomains: [], dkimDomains: [], envelopeFroms: [], sender: null, catalogue: null
};
const v = (over) => sourceVerdict({ ...base, ...over });

check("orgDomain", orgDomain("bounce.mail.example.com") === "example.com" && orgDomain("example.com") === "example.com");

check("passing", v({ failed: 0, spfPassed: 100 }).code === "pass");
check("no messages", v({ total: 0, failed: 0 }).code === "none");
check("forwards only", v({ failed: 20, likelyForwards: 20, spfPassed: 80 }).code === "forward");

// The ESP case: SPF passes for the service's bounce domain, DKIM signed by the service.
const esp = v({ spfRawPass: 100, spfDomains: ["bounces.sendgrid.net"], dkimRawPass: 100, dkimSigned: 100, dkimDomains: ["sendgrid.net"], catalogue: { name: "SendGrid", pattern: "*.sendgrid.net", spfInclude: "include:sendgrid.net", dkimHint: "Complete Sender Authentication." } });
check("ESP: SPF unaligned headline names the service", esp.code === "unaligned" && /SPF unaligned \(SendGrid\)/.test(esp.headline), esp.headline);
check("ESP: detail names the foreign domains", /bounces\.sendgrid\.net/.test(esp.detail) && /signed by sendgrid\.net/.test(esp.detail), esp.detail);
check("ESP: action is custom DKIM with the catalogue hint", /custom DKIM for example\.com at SendGrid/.test(esp.action) && /Sender Authentication/.test(esp.action), esp.action);

const noDkim = v({ spfRawPass: 100, spfDomains: ["mailer.example.net"] });
check("SPF unaligned without any DKIM: turn on signing", noDkim.code === "unaligned" && /no DKIM signature/.test(noDkim.detail) && /Turn on DKIM signing for example\.com/.test(noDkim.action), noDkim.action);

const brokenDkim = v({ spfRawPass: 100, spfDomains: ["mailer.example.net"], dkimSigned: 100, dkimDomains: ["example.com"] });
check("SPF unaligned with a broken aligned signature: fix the key", brokenDkim.code === "unaligned" && /does not verify/.test(brokenDkim.action), brokenDkim.action);

const dkimOnly = v({ dkimRawPass: 100, dkimSigned: 100, dkimDomains: ["mandrillapp.com"] });
check("no SPF, DKIM by another domain", dkimOnly.code === "unaligned" && /DKIM unaligned/.test(dkimOnly.headline) && /signed by mandrillapp\.com/.test(dkimOnly.detail));

const ours = v({ sender: { kind: "ours", label: "Office printer" }, catalogue: { name: "GoDaddy", pattern: "*.secureserver.net", spfInclude: "include:secureserver.net", dkimHint: "" } });
check("labelled ours with nothing vouching: not authorised, SPF include named", ours.code === "unauthorised" && /Office printer/.test(ours.headline) && /Add include:secureserver\.net to your SPF record/.test(ours.action), ours.action);

const spoof = v({});
check("unknown source, nothing vouching: spoof", spoof.code === "spoof" && /Nothing vouches/.test(spoof.headline) && /spoofing/.test(spoof.detail));
const spoofKnownService = v({ catalogue: { name: "Amazon SES", pattern: "*.amazonses.com", spfInclude: "include:amazonses.com", dkimHint: "" } });
check("unknown source at a known service is named", /Unauthorised \(Amazon SES\)/.test(spoofKnownService.headline) && /belongs to Amazon SES/.test(spoofKnownService.detail));

const partial = v({ failed: 10, spfPassed: 90, dkimPassed: 90, spfRawPass: 90, dkimRawPass: 90, dkimSigned: 100, dkimDomains: ["example.com"] });
check("partly failing with broken signatures", partial.code === "partial" && /10 of 100/.test(partial.detail) && /do not verify/.test(partial.detail) && /DKIM key in DNS/.test(partial.action), partial.detail);
const partialStreams = v({ failed: 10, spfPassed: 90, spfRawPass: 90 });
check("partly failing without DKIM clue: look at streams", partialStreams.code === "partial" && /which stream fails/.test(partialStreams.action));

check("forwards are excluded before judging", v({ failed: 30, likelyForwards: 25, spfPassed: 70, spfRawPass: 70 }).code === "partial");

// --- catalogue ---
check("catalogue: every entry has a name, patterns and a DKIM hint", CATALOGUE.every((e) => e.name && e.patterns.length && typeof e.dkimHint === "string"));
const m365 = matchCatalogue("40.107.22.51", "mail-bn8nam12on2051.outbound.protection.outlook.com");
check("catalogue: Microsoft 365 by PTR", m365 && m365.name === "Microsoft 365" && m365.spfInclude === "include:spf.protection.outlook.com");
check("catalogue: Microsoft 365 by network without PTR", matchCatalogue("40.107.22.51", null)?.name === "Microsoft 365");
check("catalogue: Google by IPv6 range", matchCatalogue("2a00:1450:4864:20::52a", null)?.name === "Google Workspace");
const sg = matchCatalogue("198.51.100.7", "o1.ptr1234.sendgrid.net");
check("catalogue: SendGrid by PTR carries the matched pattern", sg && sg.name === "SendGrid" && sg.pattern === "*.sendgrid.net");
check("catalogue: unknown host is null", matchCatalogue("203.0.113.9", "vps-9.hostbox.example") === null);
check("catalogue: consumer webmail has no SPF include", matchCatalogue("1.2.3.4", "sonic.yahoo.com")?.spfInclude === null);

process.exitCode = report() ? 0 : 1;
