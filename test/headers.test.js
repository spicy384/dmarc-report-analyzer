/** Email header analysis: parsing, alignment, hops, signatures, source, Microsoft stamps. */
const fs = require("fs");
const path = require("path");
const { createChecker } = require("./helpers/assert");
const { createHeaderAnalyzer, parseHeaderBlock, parseAddress, parseReceived, parseAuthResults, parseReceivedSpf, parseDkimSignature, findIps, isPrivateIp, compauthMeaning, formatDuration } = require("../header-analyzer");

const { check, report } = createChecker("Header analyzer");
const sample = fs.readFileSync(path.join(__dirname, "..", "examples", "sample-headers.txt"), "utf8");
const NOW = Date.parse("2026-10-01T00:00:00Z") / 1000;

// --- pure parsing ---------------------------------------------------------------------
const block = parseHeaderBlock(`\n\n${sample}\n\nbody text: not a header\nX-Not: a header`);
check("header block: folded lines joined, body ignored", block.length === 21 && block.filter((h) => h.name === "Received").length === 5 && !block.some((h) => h.name === "X-Not") && block.find((h) => h.name === "Subject").value === "Your September invoice", String(block.length));
check("parseAddress: name, address, domain; encoded words", parseAddress('"Example Billing" <Billing@Example.com>').address === "billing@example.com" && parseAddress('"Example Billing" <Billing@Example.com>').name === "Example Billing" && parseAddress("=?utf-8?B?SsO8cmdlbg==?= <j@x.test>").name === "Jürgen" && parseAddress("plain@x.test").domain === "x.test" && parseAddress(null) === null);
const hop = parseReceived("from o1.ptr1234.sendgrid.net (167.89.12.34) by DM6NAM11FT001.mail.protection.outlook.com (10.13.172.10) with Microsoft SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.7982.25 via Frontend Transport; Mon, 28 Sep 2026 14:03:09 +0000");
check("parseReceived: from, public ip, by, tls, date", hop.from === "o1.ptr1234.sendgrid.net" && hop.fromIp === "167.89.12.34" && hop.by === "dm6nam11ft001.mail.protection.outlook.com" && hop.tls === "TLS1_3" && hop.date === Date.parse("2026-09-28T14:03:09Z") / 1000 && hop.id === "15.20.7982.25", JSON.stringify(hop));
const hop2 = parseReceived("from app-server-7 (unknown [198.51.100.20]) by ismtpd0001p1iad1.sendgrid.net (SG) with ESMTP id AbC for <Jane@Contoso.com>; Mon, 28 Sep 2026 14:02:54 +0000 (UTC)");
check("parseReceived: bracketed ip, for, trailing comment on the date", hop2.fromIp === "198.51.100.20" && hop2.for === "jane@contoso.com" && hop2.with === "ESMTP" && hop2.date !== null && hop2.tls === null);
check("findIps / isPrivateIp", findIps("x [IPv6:2001:db8::1] y (10.0.0.1) z 203.0.113.9").join() === "2001:db8::1,10.0.0.1,203.0.113.9" && isPrivateIp("10.0.0.1") && isPrivateIp("fd00::1") && !isPrivateIp("203.0.113.9") && !isPrivateIp("2603:10b6::1"));
const ar = parseAuthResults("mx.google.com; dkim=pass header.i=@evil-mail.test header.s=k1 header.b=abc; spf=pass (google.com: domain of bounce@evil-mail.test designates 203.0.113.77 as permitted sender) smtp.mailfrom=bounce@evil-mail.test; dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE) header.from=example.com");
check("parseAuthResults: authserv-id, methods, props, comments with semicolons inside parentheses", ar.authservId === "mx.google.com" && ar.results.length === 3 && ar.results[0].props["header.s"] === "k1" && ar.results[1].comment.includes("designates 203.0.113.77") && ar.results[2].result === "fail" && ar.results[2].props["header.from"] === "example.com", JSON.stringify(ar));
check("parseAuthResults: Microsoft form without authserv-id, ARC instance", parseAuthResults("spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=a.test; dkim=none (message not signed) header.d=none;dmarc=pass action=none header.from=a.test;compauth=pass reason=100").results.length === 4 && parseAuthResults("i=2; mx.x.test; dkim=pass header.d=a.test").instance === 2);
const rs = parseReceivedSpf("Pass (protection.outlook.com: domain of em.example.com designates 167.89.12.34 as permitted sender) receiver=protection.outlook.com; client-ip=167.89.12.34; helo=o1.sendgrid.net; pr=C");
check("parseReceivedSpf", rs.result === "pass" && rs.clientIp === "167.89.12.34" && rs.helo === "o1.sendgrid.net");
const sig = parseDkimSignature("v=1; a=rsa-sha256; d=Example.com; s=s1; h=from:to:subject; x=1700000000; l=100; bh=x; b=y", { now: NOW });
check("parseDkimSignature: tags, expiry, l=, From coverage", sig.domain === "example.com" && sig.selector === "s1" && sig.expired === true && sig.bodyLength === "100" && sig.signsFrom === true && parseDkimSignature("d=a.test; s=x; h=to:subject", { now: NOW }).signsFrom === false);
check("compauthMeaning / formatDuration", compauthMeaning("fail", "001").includes("implicit failure") && compauthMeaning("pass", "100").includes("explicit") && compauthMeaning("fail", "601").includes("accepted domains") && formatDuration(75) === "1 min 15 s" && formatDuration(7500) === "2 h 5 min");

// --- full analysis, offline -----------------------------------------------------------
const dnsRecords = {
  getDmarc: async (d) => (d === "example.com" ? { domain: d, found: true, record: "v=DMARC1; p=reject", tags: { p: "reject" }, inheritedFrom: null } : { domain: d, found: false, tags: {} }),
  checkDkim: async (d, s) => (d === "example.com" && s === "s1" ? { found: true, keyType: "rsa", keyBits: 2048, weak: false } : { found: false }),
  getPtr: async (ip) => (ip === "167.89.12.34" ? { found: true, names: [{ name: "o1.ptr1234.sendgrid.net", confirmed: true }] } : { found: false, names: [] })
};
const db = {
  ips: (_f, { ip }) => (ip === "167.89.12.34" ? [{ ip, total: 420, failed: 3, firstSeen: 1, lastSeen: 2 }] : []),
  senderFor: (ip) => (ip === "167.89.12.34" ? { id: 1, kind: "vendor", label: "SendGrid", pattern: "*.sendgrid.net" } : null)
};
const geoip = { lookup: async (ips) => new Map(ips.map((ip) => [ip, { country: "United States", countryCode: "US", city: null, asn: 11377, asOrg: "SendGrid, Inc.", source: "file" }])) };
const analyzer = createHeaderAnalyzer({ dnsRecords, db, geoip, now: () => NOW });

(async () => {
  const a = await analyzer.analyze(sample);
  check("summary: who, what, when", a.summary.from.address === "billing@example.com" && a.summary.returnPath.domain === "em1234.example.com" && a.summary.subject === "Your September invoice" && a.summary.messageId === "<AbCdEfGhQ_abc123@geopod-ismtpd-1>" && a.summary.date === Date.parse("2026-09-28T14:02:54Z") / 1000);
  check("verdicts: SPF pass and aligned (relaxed), DKIM pass and aligned, DMARC pass via both", a.verdicts.spf.result === "pass" && a.verdicts.spf.domain === "em1234.example.com" && a.verdicts.spf.aligned === true && a.verdicts.dkim.aligned === true && a.verdicts.dkim.alignedDomains[0] === "example.com" && a.verdicts.dmarc.reported === "pass" && a.verdicts.dmarc.computed === "pass" && a.verdicts.dmarc.via.join() === "SPF,DKIM" && a.verdicts.dmarc.policy === "reject" && a.verdicts.dmarc.action === "none", JSON.stringify(a.verdicts));
  check("hops: oldest first with delays", a.hops.length === 5 && a.hops[0].by === "ismtpd0001p1iad1.sendgrid.net" && a.hops[0].delaySeconds === null && a.hops[1].delaySeconds === 15 && a.hops[4].with === "HTTPS" && a.transit.totalSeconds === 18 && a.transit.slowest.seconds === 15 && a.transit.slowest.index === 2, JSON.stringify(a.hops.map((h) => [h.by, h.delaySeconds])));
  check("signature: parsed, matched to the receiver's result, key checked in DNS", a.signatures.length === 1 && a.signatures[0].selector === "s1" && a.signatures[0].result === "pass" && a.signatures[0].aligned === true && a.signatures[0].dns.keyBits === 2048 && a.signatures[0].signsFrom === true);
  check("source: from the receiver's SPF check, enriched", a.source.ip === "167.89.12.34" && /SPF check/.test(a.source.how) && a.source.ptr === "o1.ptr1234.sendgrid.net" && a.source.ptrConfirmed === true && a.source.catalogue.name === "SendGrid" && a.source.known.label === "SendGrid" && a.source.seen.total === 420 && a.source.geo.asOrg === "SendGrid, Inc.", JSON.stringify(a.source));
  check("microsoft: SCL, BCL, SFV, CAT, compauth decoded", a.microsoft.scl === 1 && a.microsoft.sclMeaning === "not spam" && a.microsoft.bcl === 2 && a.microsoft.sfv === "NSPM" && a.microsoft.cat === "NONE" && a.microsoft.cip === "167.89.12.34" && a.microsoft.direction === "INB" && a.microsoft.authAs === "Anonymous" && a.microsoft.compauth.reason === "100" && a.microsoft.compauth.meaning.includes("explicit"), JSON.stringify(a.microsoft));
  const texts = a.findings.map((f) => `${f.severity}: ${f.text}`);
  check("findings: DMARC pass, envelope note, delivery time, known sender", texts.some((t) => t.startsWith("good: DMARC passes for example.com")) && texts.some((t) => t.startsWith("info: The envelope sender")) === false && texts.some((t) => /Delivered in 18 s over 5 hops/.test(t)) && texts.some((t) => t.startsWith("good: Handed to the receiver by 167.89.12.34") && /SendGrid/.test(t) && /420 messages, 3 failing/.test(t)), texts.join("\n"));
  check("all headers returned in order", a.headers.length === 21 && a.headers[0].name === "Received" && a.counts.hops === 5);

  // --- a spoof: authenticated as someone else, display name disguised, replies diverted ---
  const spoof = [
    "Delivered-To: jane@contoso.com",
    "Received: by 2002:a05:6a10:1234:b0:1:2:3:4 with SMTP id x1csp123; Tue, 29 Sep 2026 09:00:08 -0700 (PDT)",
    "Authentication-Results: mx.google.com; dkim=pass header.i=@evil-mail.test header.s=k1 header.b=abc;",
    "       spf=pass (google.com: domain of bounce@evil-mail.test designates 203.0.113.77 as permitted sender) smtp.mailfrom=bounce@evil-mail.test;",
    "       dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE) header.from=example.com",
    "Received: from mail.evil-mail.test (mail.evil-mail.test. [203.0.113.77]) by mx.google.com with ESMTPS id abc for <jane@contoso.com> (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256); Tue, 29 Sep 2026 08:00:07 -0700 (PDT)",
    "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=evil-mail.test; s=k1; h=subject:to; l=20; bh=x; b=y",
    'From: "IT Support <helpdesk@example.com>" <helpdesk@example.com>',
    "Reply-To: collector@freemail.test",
    "Return-Path: <bounce@evil-mail.test>",
    "Subject: Password expiry",
    "Message-ID: <1@evil-mail.test>",
    "Date: Tue, 29 Sep 2026 15:00:05 +0000",
    "X-Spam-Status: Yes, score=7.2 required=5.0"
  ].join("\r\n");
  const s = await analyzer.analyze(spoof);
  check("spoof: SPF and DKIM pass for another domain, so DMARC fails; agrees with the receiver", s.verdicts.spf.result === "pass" && s.verdicts.spf.aligned === false && s.verdicts.dkim.passingDomains[0] === "evil-mail.test" && s.verdicts.dkim.aligned === false && s.verdicts.dmarc.computed === "fail" && s.verdicts.dmarc.reported === "fail" && s.verdicts.dmarc.policy === "reject", JSON.stringify(s.verdicts));
  const st = s.findings.map((f) => `${f.severity}: ${f.text}`);
  check("spoof findings: failure explained, policy consequence, reply-to, signature problems, slow hop", st.some((t) => t.startsWith("bad: DMARC fails for example.com") && /evil-mail\.test/.test(t)) && st.some((t) => /p=reject/.test(t)) && st.some((t) => /Replies go to collector@freemail\.test/.test(t)) && st.some((t) => /does not cover the From header/.test(t)) && st.some((t) => /l=20/.test(t)) && st.some((t) => /No DKIM key is published at k1\._domainkey\.evil-mail\.test/.test(t)) && st.some((t) => /Delivery took 1 h/.test(t)), st.join("\n"));
  check("spoof: source from the SPF comment, unknown to the reports; other filter headers listed", s.source.ip === "203.0.113.77" && s.source.known === null && s.source.seen === null && s.microsoft === null && s.otherFilters.some((o) => o.name === "X-Spam-Status"));
  const disguised = await analyzer.analyze('From: "ceo@example.com" <random@freemail.test>\nSubject: hi\nDate: Tue, 29 Sep 2026 15:00:05 +0000\n');
  check("disguised display name is called out; no auth results is a warning", disguised.findings.some((f) => f.severity === "bad" && /display name shows a different address/.test(f.text)) && disguised.findings.some((f) => /No Authentication-Results header/.test(f.text)) && disguised.verdicts.dmarc.computed === null);

  // --- input validation ---
  const bad = async (input) => analyzer.analyze(input).then(() => null, (e) => e);
  check("empty input is a 400", (await bad("  ")).status === 400);
  check("prose is a 400 with guidance", (await bad("hello there\nthis is not it")).status === 400 && /Show original/.test((await bad("hello there\nthis is not it")).message));
  check("oversized input is a 413", (await bad(`Subject: x\n${"X-Pad: ".padEnd(600 * 1024, "a")}`)).status === 413);

  // Without any lookups the analysis still works from the headers alone.
  const offline = await createHeaderAnalyzer({ now: () => NOW }).analyze(sample);
  check("no dns/db/geo: still analyses", offline.verdicts.dmarc.computed === "pass" && offline.dmarcRecord === null && offline.source.ip === "167.89.12.34" && offline.source.ptr === "o1.ptr1234.sendgrid.net" && offline.signatures[0].dns === null);

  process.exit(report() ? 0 : 1);
})().catch((error) => { console.error(error); process.exit(1); });
