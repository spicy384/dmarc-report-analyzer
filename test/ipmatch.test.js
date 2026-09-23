/** IP, CIDR and reverse-DNS pattern matching. */
const { createChecker } = require("./helpers/assert");
const ipmatch = require("../ipmatch");

const { check, report } = createChecker("ipmatch: IPv4/IPv6 parsing, CIDR, hostname patterns");

// --- parsing ----------------------------------------------------------------
check("v4 parses", ipmatch.parseIp("192.0.2.10").value === 3221225994n && ipmatch.parseIp("192.0.2.10").version === 4);
check("v4 rejects out-of-range", ipmatch.parseIp("256.1.1.1") === null && ipmatch.parseIp("1.2.3") === null);
check("v6 parses", ipmatch.parseIp("2001:db8::1").value === 0x20010db8000000000000000000000001n);
check("v6 full form", ipmatch.parseIp("2001:0db8:0000:0000:0000:0000:0000:0001").value === 0x20010db8000000000000000000000001n);
check("v6 embedded v4", ipmatch.parseIp("::ffff:192.0.2.10").value === 0xffffc000020an);
check("v6 with zone id", ipmatch.parseIp("fe80::1%eth0").version === 6);
check("v6 rejects double ::", ipmatch.parseIp("1::2::3") === null);
check("v6 rejects too many groups", ipmatch.parseIp("1:2:3:4:5:6:7:8:9") === null);
check("garbage is null", ipmatch.parseIp("mail.example.com") === null && ipmatch.parseIp("") === null);

// --- cidr -------------------------------------------------------------------
const c16 = ipmatch.parseCidr("40.107.0.0/16");
check("v4 cidr", c16 && c16.bits === 16 && ipmatch.cidrContains(c16, ipmatch.parseIp("40.107.22.51")) && !ipmatch.cidrContains(c16, ipmatch.parseIp("40.108.0.1")));
check("bare ip is a /32", ipmatch.parseCidr("10.0.0.1").bits === 32 && ipmatch.cidrContains(ipmatch.parseCidr("10.0.0.1"), ipmatch.parseIp("10.0.0.1")) && !ipmatch.cidrContains(ipmatch.parseCidr("10.0.0.1"), ipmatch.parseIp("10.0.0.2")));
const c6 = ipmatch.parseCidr("2a01:111:f400::/48");
check("v6 cidr", c6 && ipmatch.cidrContains(c6, ipmatch.parseIp("2a01:111:f400:fe0a::701")) && !ipmatch.cidrContains(c6, ipmatch.parseIp("2a01:111:f401::1")));
check("/0 matches everything", ipmatch.cidrContains(ipmatch.parseCidr("0.0.0.0/0"), ipmatch.parseIp("203.0.113.1")));
check("bad prefix", ipmatch.parseCidr("10.0.0.0/33") === null && ipmatch.parseCidr("10.0.0.0/x") === null);
check("version mismatch never matches", !ipmatch.cidrContains(c16, ipmatch.parseIp("::ffff:40.107.1.1")));

// --- patterns ---------------------------------------------------------------
check("pattern: cidr", ipmatch.parsePattern("40.107.0.0/16").type === "cidr");
check("pattern: suffix", ipmatch.parsePattern("*.outbound.protection.outlook.com").type === "suffix");
check("pattern: host", ipmatch.parsePattern("Mail-A.Google.COM").type === "host" && ipmatch.parsePattern("Mail-A.Google.COM").host === "mail-a.google.com");
check("pattern: junk", ipmatch.parsePattern("not a host") === null && ipmatch.parsePattern("*.") === null && ipmatch.parsePattern("") === null);

// --- finding the best match --------------------------------------------------
const compiled = ipmatch.compileSenders([
  { id: 1, pattern: "40.107.0.0/16", label: "Microsoft 365 (wide)" },
  { id: 2, pattern: "40.107.22.51", label: "Microsoft 365 (exact)" },
  { id: 3, pattern: "*.outbound.protection.outlook.com", label: "Microsoft 365 (ptr)" },
  { id: 4, pattern: "mail20.atl71.mcsv.net", label: "Mailchimp host" },
  { id: 5, pattern: "garbage pattern", label: "dropped" },
  { id: 6, pattern: "2a01:111:f400::/48", label: "Microsoft v6" }
]);
check("invalid patterns are dropped", compiled.length === 5);
check("exact ip beats the block", ipmatch.findSender(compiled, "40.107.22.51", null).id === 2);
check("block matches other addresses", ipmatch.findSender(compiled, "40.107.99.1", null).id === 1);
check("ptr suffix matches when ip does not", ipmatch.findSender(compiled, "52.100.1.1", "mail-bn8nam12on2051.outbound.protection.outlook.com").id === 3);
check("ptr suffix matches the bare domain too", ipmatch.findSender(compiled, "52.100.1.1", "outbound.protection.outlook.com").id === 3);
check("ptr suffix is a label boundary", ipmatch.findSender(compiled, "52.100.1.1", "notoutbound.protection.outlook.com") === null);
check("exact host, case-insensitive, trailing dot ok", ipmatch.findSender(compiled, "198.2.128.20", "MAIL20.atl71.mcsv.net.").id === 4);
check("v6 block", ipmatch.findSender(compiled, "2a01:111:f400:7e1c::701", null).id === 6);
check("no match", ipmatch.findSender(compiled, "185.220.101.7", null) === null && ipmatch.findSender(compiled, "not-an-ip", "x.example") === null);
check("specificity ordering", ipmatch.specificity(ipmatch.parsePattern("1.2.3.4")) > ipmatch.specificity(ipmatch.parsePattern("1.2.3.0/24")));

process.exit(report() ? 0 : 1);
