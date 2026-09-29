/**
 * Well-known sending services, recognised by reverse-DNS suffix (stable for years)
 * and, for the two biggest, by published network ranges. A match is only a hint
 * shown next to unlabelled sources ("looks like SendGrid"); the user decides
 * whether to label it, and a label they add always wins over the catalogue.
 *
 * Each entry carries what the verdicts need: the SPF include the service asks
 * for and how to get DKIM signed with your own domain there.
 */
const { compileSenders, findSender } = require("./ipmatch");

const CATALOGUE = [
  {
    name: "Microsoft 365",
    patterns: ["*.outbound.protection.outlook.com", "40.92.0.0/15", "40.107.0.0/16", "52.100.0.0/14", "104.47.0.0/17", "2a01:111:f400::/48", "2a01:111:f403::/48"],
    spfInclude: "include:spf.protection.outlook.com",
    dkimHint: "In the Defender portal, Email authentication settings > DKIM, enable signing for the domain and publish the two selector CNAMEs."
  },
  {
    name: "Google Workspace",
    patterns: ["*.google.com", "209.85.128.0/17", "64.233.160.0/19", "66.102.0.0/20", "66.249.80.0/20", "72.14.192.0/18", "74.125.0.0/16", "108.177.8.0/21", "173.194.0.0/16", "2001:4860:4000::/36", "2404:6800:4000::/36", "2607:f8b0:4000::/36", "2800:3f0:4000::/36", "2a00:1450:4000::/36", "2c0f:fb50:4000::/36"],
    spfInclude: "include:_spf.google.com",
    dkimHint: "In the Google Admin console, Apps > Google Workspace > Gmail > Authenticate email, generate a key for the domain and publish the TXT record."
  },
  { name: "SendGrid", patterns: ["*.sendgrid.net", "167.89.0.0/17", "168.245.0.0/17", "149.72.0.0/16", "159.183.0.0/16"], spfInclude: "include:sendgrid.net", dkimHint: "Complete Sender Authentication (domain authentication) in SendGrid and publish its CNAMEs; that signs with your domain instead of sendgrid.net." },
  { name: "Mailchimp", patterns: ["*.mcsv.net", "*.mcdlv.net", "*.rsgsv.net"], spfInclude: "include:servers.mcsv.net", dkimHint: "Authenticate the domain in Mailchimp (Domains > Authenticate) and publish its CNAMEs." },
  { name: "Mandrill", patterns: ["*.mandrillapp.com"], spfInclude: "include:spf.mandrillapp.com", dkimHint: "Add the domain under Sending Domains in Mandrill and publish its DKIM record." },
  { name: "Amazon SES", patterns: ["*.amazonses.com"], spfInclude: "include:amazonses.com", dkimHint: "Verify the domain in SES with Easy DKIM and publish the three CNAMEs; also set a custom MAIL FROM domain so SPF aligns." },
  { name: "Postmark", patterns: ["*.mtasv.net"], spfInclude: "include:spf.mtasv.net", dkimHint: "Verify the domain in Postmark (Sender Signatures > Domains) and publish its DKIM record and Return-Path CNAME." },
  { name: "Mailgun", patterns: ["*.mailgun.net", "*.mailgun.org"], spfInclude: "include:mailgun.org", dkimHint: "Verify the sending domain in Mailgun and publish its DKIM TXT record." },
  { name: "Brevo", patterns: ["*.sendinblue.com", "*.brevo.com"], spfInclude: "include:spf.brevo.com", dkimHint: "Authenticate the domain in Brevo (Senders & IP > Domains) and publish its DKIM records." },
  { name: "HubSpot", patterns: ["*.hubspotemail.net"], spfInclude: "include:_spf.hubspotemail.net", dkimHint: "Connect the email sending domain in HubSpot and publish its two DKIM CNAMEs." },
  { name: "Salesforce", patterns: ["*.salesforce.com", "*.exacttarget.com"], spfInclude: "include:_spf.salesforce.com", dkimHint: "Create a DKIM key under Email Administration in Salesforce, publish the CNAMEs and activate it." },
  { name: "Zoho", patterns: ["*.zoho.com", "*.zohomail.com"], spfInclude: "include:zohomail.com", dkimHint: "Add a DKIM selector for the domain in Zoho Mail admin and publish the TXT record." },
  { name: "Zendesk", patterns: ["*.zendesk.com"], spfInclude: "include:mail.zendesk.com", dkimHint: "Enable Digitally sign outbound email in Zendesk and publish its two CNAMEs." },
  { name: "Freshdesk", patterns: ["*.freshdesk.com", "*.freshemail.io"], spfInclude: "include:email.freshdesk.com", dkimHint: "Configure DKIM for the domain under Email settings in Freshdesk and publish its CNAMEs." },
  { name: "Constant Contact", patterns: ["*.ccsend.com", "*.constantcontact.com"], spfInclude: "include:spf.constantcontact.com", dkimHint: "Enable self-authentication in Constant Contact and publish the DKIM record." },
  { name: "Klaviyo", patterns: ["*.klaviyomail.com"], spfInclude: "include:_spf.klaviyo.com", dkimHint: "Set up a dedicated sending domain in Klaviyo and publish its records." },
  { name: "Shopify", patterns: ["*.shopifyemail.com"], spfInclude: "include:shops.shopify.com", dkimHint: "Authenticate the sender domain in Shopify's notification settings and publish its CNAMEs." },
  { name: "Intercom", patterns: ["*.intercom-mail.com"], spfInclude: "include:_spf.intercom.io", dkimHint: "Add a custom sender domain in Intercom and publish its DKIM CNAME." },
  { name: "Proofpoint", patterns: ["*.pphosted.com", "*.ppe-hosted.com"], spfInclude: null, dkimHint: "Proofpoint relays your own mail: sign with DKIM at the origin or configure DKIM signing in the Proofpoint console." },
  { name: "Mimecast", patterns: ["*.mimecast.com", "*.mimecast.co.za", "*.mimecast-offshore.com"], spfInclude: "include:_netblocks.mimecast.com", dkimHint: "Configure a DKIM signing definition for the domain in the Mimecast console." },
  { name: "Barracuda", patterns: ["*.barracudanetworks.com", "*.ess.barracudanetworks.com"], spfInclude: "include:spf.ess.barracuda.com", dkimHint: "Enable DKIM signing for the domain in Barracuda Email Gateway Defense." },
  { name: "GoDaddy", patterns: ["*.secureserver.net"], spfInclude: "include:secureserver.net", dkimHint: "GoDaddy shared hosting cannot sign with your domain; move the mail to a service that supports DKIM." },
  { name: "Rackspace", patterns: ["*.emailsrvr.com"], spfInclude: "include:emailsrvr.com", dkimHint: "Enable DKIM for the domain in the Rackspace Cloud Office control panel and publish its record." },
  { name: "iCloud Mail", patterns: ["*.icloud.com", "*.apple.com"], spfInclude: "include:icloud.com", dkimHint: "Custom-domain iCloud Mail signs automatically once the domain is verified in iCloud settings." },
  { name: "Yahoo", patterns: ["*.yahoo.com", "*.yahoodns.net", "*.aol.com"], spfInclude: null, dkimHint: "Consumer Yahoo and AOL mail cannot be signed for your domain; if this is a user sending as your domain, it will keep failing." },
  { name: "Outlook.com (consumer)", patterns: ["*.outlook.com", "*.hotmail.com"], spfInclude: null, dkimHint: "Consumer Outlook.com mail cannot be signed for your domain; if this is a user sending as your domain, move them to Microsoft 365." },
  { name: "Gmail (consumer)", patterns: ["*.googlemail.com"], spfInclude: null, dkimHint: "Consumer Gmail cannot be signed for your domain; if this is a user sending as your domain, move them to Google Workspace." }
];

let compiled = null;

function compiledCatalogue() {
  if (!compiled) {
    const rows = [];
    for (const entry of CATALOGUE) {
      for (const pattern of entry.patterns) rows.push({ pattern, entry });
    }
    compiled = compileSenders(rows);
  }
  return compiled;
}

/** { name, pattern, spfInclude, dkimHint } for a known service, else null. */
function matchCatalogue(ip, ptr) {
  const hit = findSender(compiledCatalogue(), ip, ptr);
  if (!hit) return null;
  const { entry, pattern } = hit;
  return { name: entry.name, pattern, spfInclude: entry.spfInclude, dkimHint: entry.dkimHint };
}

module.exports = { CATALOGUE, matchCatalogue };
