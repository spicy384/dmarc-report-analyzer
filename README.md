# DMARC Report Analyzer

Small web app that reads DMARC aggregate reports out of a Microsoft 365 mailbox, stores
them in SQLite, and shows what they say: how much mail failed DMARC, which IP addresses
sent it, when, who reported it, and which domains were involved. Runs as a container on a
management server.

## What it shows

**Overview** for any period and domain: messages seen, DMARC pass and fail percentages,
how many failures were quarantined or rejected, how many source IPs are failing, and a
per-day bar chart of pass vs. fail split by what the receiver did with it.

**Sending sources**: every IP that sent mail claiming your domain, worst first, with
reverse DNS, message and failure counts, what happened to the failures, SPF and DKIM
alignment rates, the SPF/DKIM domains actually seen, which services reported it and when
it was last seen. Click a row for the individual records behind it. A source that fails
everything and is not yours is spoofing; one that fails but is yours needs SPF or DKIM
fixed.

**This week**: seven days against the seven before for the selected domain and mailbox:
messages, pass rate, failures and forwards, quarantined and rejected, failing sources and
reporters, plus the sources that appeared for the first time this week, the top failing
sources and the top forwarders. Step back week by week, and **Copy as text** produces a
plain summary to paste into an email or a Teams post.

**Policy readiness**: for a domain, the DMARC record as published right now with its
tags explained and warnings (no record, `p=none`, `pct` below 100, no `rua`, reports going
to an address the analyzer does not read), the SPF record expanded through its includes
with the DNS-lookup count against the limit of 10, which of your labelled senders fail
SPF and are missing from it, the DKIM selectors seen in reports and whether each still
resolves, and **what `p=reject` would have done** in the selected period: legitimate mail
that would have been rejected (from sources labelled yours or vendor), spoofing that would
have been blocked, and forwards that would have been lost. A domain is called ready when
nothing legitimate would be rejected and every failing source has a label.

**Why it fails**: every source in the Sending sources table gets a one-line verdict, with
the full reasoning and the fix in its drawer: SPF passes only for the sending service's own
domain (the classic mailing-platform case), DKIM signed by another domain, no signature at
all, a labelled sender that nothing vouches for, forwards only, partly failing streams, or
nothing vouching for an unknown source, which is what reject is for. Sources at
well-known services (Microsoft 365, Google Workspace, SendGrid, Mailchimp, Amazon SES,
Postmark, Mailgun and others) are recognised by reverse DNS or network and shown as
"looks like SendGrid" until you label them, which is then one click, and the verdict's
fix names that service's SPF include and where to turn on custom DKIM.

**Trend at a glance**: each source has a sparkline of its daily volume over the period
(failures in red, bucketed so long periods still fit), and clicking a day in the main
chart narrows the whole dashboard to that day.

**Two pages**: the dashboard holds the analysis panels; **Settings** in the header holds
Mailbox sync, Users and Account, so the dashboard stays short. Every non-default filter
(domain, mailbox, search, hidden forwards) is listed in a "Showing only" strip under the
filter bar with a **Clear filters** button, because a search left over from an alert's
**Show** button or the lookup panel's **Open in sources** otherwise looked like missing data.

**DNS lookup**: check any domain or IP address, whether or not it appears in your reports.
A domain gets its DMARC record (with the same warnings as the policy panel), its SPF record
expanded into the networks it authorises, its MX hosts with their addresses (null MX and
hosts that do not resolve are called out) and its A/AAAA addresses. An IP gets its reverse
DNS with a forward check (a PTR name that resolves back to the address is forward-confirmed,
which is what receivers expect from a mail server) plus what the analyzer already knows about
it: label, report totals, network. Hosts and addresses in the results are clickable to look
them up in turn, and the query is kept in the page link.

**Known senders**: label the sources you recognise so the analyzer can tell "yours" from
"not yours". A pattern is an IP, a CIDR block, a host name or `*.suffix` matched against
reverse DNS; the kind is **ours** (your tenant, your relay), **vendor** (sends on your
behalf) or **other**. Every source is then tagged, the overview splits failures into
yours (fix SPF or DKIM) and not yours (spoofing), and **Import from SPF** resolves your
SPF record through its includes and proposes the networks it authorises, for you to tick
and add. Nothing is added automatically.

**Alerts**: after every sync that adds reports, the analyzer flags a **new source** (an IP
failing DMARC that had never appeared before and is not a known sender), a **spike** (a
source whose non-forward failures in the last 7 days are at least three times the previous
7 days, with at least 20 messages) and, for information, the **first reports** from a new
reporting service. Open alerts sit in a banner at the top of the page with a Show button
that searches for the source, and they stay until someone acknowledges them. The count
also appears in the browser tab title.

**Reporting services**: which receivers (Google, Microsoft, Yahoo, ...) sent reports, how
many, and the failure rate each of them saw.

**Reports**: every report with its window, reporter, domain, published policy and counts.
Click one for its records; the original XML can be downloaded.

**Search**: one box that narrows every panel at once. It matches source IPs, reverse DNS
names, From and envelope domains, the SPF and DKIM domains seen, reporter names and
report IDs, so typing an IP shows that sender's history and typing a reporter shows only
their reports.

**Hide likely forwards**: DMARC counts forwarded and mailing-list mail as failures, which
buries real spoofing under noise from legitimate relays. Ticking this hides failures that
look like forwards: the reporter tagged them (`forwarded`, `mailing_list`,
`trusted_forwarder`), or a DKIM signature for your own domain was present but no longer
verified, meaning the message was signed by you and altered on the way. A spoofer has no
signature for your domain at all. Forwarded mail that was never DKIM-signed cannot be
told apart from spoofing and stays visible. Such records are also tagged "likely forward"
in every record list.

**Find the emails in Exchange Online**: opening a report shows ready-to-paste queries
for its window, and clicking any individual record (inside a report, or one of the
reports listed under a source IP) shows queries scoped to that record's window and IP:
a `Get-MessageTraceV2` command (the current cmdlet, ExchangeOnlineManagement 3.7.0 or
later; reaches back 90 days, at most 10 days per query, with an exact `-FromIP` filter and
a `Get-MessageTraceDetailV2` follow-up for the hops of one message), a
`Start-HistoricalSearch` command (up to 90 days, emails a CSV, useful for more than 5000
results; it needs a sender, recipient or Message-ID, so a placeholder sender is filled in
unless the record carries one), a Purview content-search KQL string, and the local-time
range to type into the admin center's message trace. The older `Get-MessageTrace` is being
retired by Microsoft and is no longer generated. A trace only sees mail that passed
through your tenant, so it finds outbound mail your Microsoft 365 sent and inbound mail it
received; mail sent from elsewhere straight to another provider never touched Exchange
Online.

**Export**: every record in the selected period as CSV, honouring the search and filters.

**Small things**: every stat tile shows the change against the previous period of the
same length (percentage points for rates, percent for counts), the sources table sorts by
any column, and the URL fragment carries the period, domain, mailbox, search, forwards
switch and any open IP or report, so a view can be bookmarked or pasted to a colleague.

**Mailbox sync**: sync on a schedule or on demand, with live progress, a run history, and a
list of emails whose attachments could not be read. Emails already ingested are skipped, so
re-running is cheap; a backfill option re-scans from any date.

### A note on "times"

Aggregate (`rua=`) reports cover a window, usually one UTC day, and give counts per source
IP. They do **not** contain a timestamp for each message. The times you see here are the
report window and when the report email arrived.

**Forensic reports** (`ruf=`, ARF format) are the exception: one email per failing
message with the exact arrival time, the source IP, the original sender, subject and
Message-ID, and the original headers. The analyzer parses them when a receiver sends
them (few large providers still do) and shows them in a **Forensic reports** panel that
appears only when there are any; each row expands to the headers and an Exchange Online
message trace scoped to the hour around the arrival time with the Message-ID, which is
as precise as a trace gets.

### Accounts

Sign-in with per-user accounts, optional TOTP two-factor and single-use recovery codes.
Administrators manage accounts and can test the mailbox connection, users can start a
sync, viewers can only look. It can also run behind an authentication reverse proxy
(Authelia, Authentik, oauth2-proxy) using the `TRUST_PROXY_AUTH` option.

**Passkeys**: anyone can add passkeys under **Account** (a phone, a laptop, a hardware
key; up to ten) and then use **Sign in with a passkey** on the sign-in card. No username,
password or code is asked for: the passkey needs the device plus a fingerprint, face or
PIN, which is the same two-factor guarantee TOTP gives the password path. The password
path stays exactly as it is, so a lost device just means signing in with the password and
adding a new passkey. Two things the browser requires: HTTPS (localhost excepted), and
reaching the app by a **hostname**, because a passkey is bound to the domain it was
created on. On plain HTTP or an IP address the passkey button is simply not shown. The
domain and origin are taken from the request; `PASSKEY_RP_ID` and `PASSKEY_ORIGIN`
override them for a proxy that rewrites hosts.

## Requirements

- A Microsoft 365 mailbox that receives the reports: the address in your domain's DMARC
  record (`v=DMARC1; p=...; rua=mailto:dmarc-reports@example.com`).
- Permission to register an application in Microsoft Entra ID and grant it admin consent.
- Docker, or Node 22+.

## Entra app registration

The app reads the mailbox with **application** permissions, so nobody has to stay signed
in and it keeps working unattended.

1. In the [Entra admin center](https://entra.microsoft.com) go to **App registrations**
   and **New registration**. Name it (for example `DMARC Report Analyzer`), leave
   *Accounts in this organizational directory only*, no redirect URI. Register.
2. On the Overview page note the **Application (client) ID** and **Directory (tenant) ID**.
3. **API permissions** → **Add a permission** → **Microsoft Graph** →
   **Application permissions** → tick **Mail.Read** → Add. Then **Grant admin consent**.
4. Give the app a credential. Either kind works, per mailbox:
   - **Client secret**: **Certificates & secrets** → **New client secret**. Copy the
     **Value** immediately; it is shown once. Note the expiry and put a reminder in your
     calendar.
   - **Certificate** (nothing to copy out of the portal, and the private key never leaves
     your server): create a key and a self-signed certificate, then upload the certificate
     under **Certificates & secrets** → **Certificates** → **Upload certificate**.

     ```bash
     openssl req -x509 -newkey rsa:2048 -sha256 -days 730 -nodes \
       -subj "/CN=dmarc-report-analyzer" -keyout graph-key.pem -out graph-cert.pem
     ```

     Upload `graph-cert.pem`; keep `graph-key.pem` private. Entra identifies the
     certificate by its SHA-1 thumbprint, which the app shows next to the mailbox. If you
     already have a `.pfx`, split it into the two PEM files with
     `openssl pkcs12 -in app.pfx -clcerts -nokeys -out graph-cert.pem` and
     `openssl pkcs12 -in app.pfx -nocerts -nodes -out graph-key.pem`. An encrypted key is
     fine too; give the passphrase alongside it.
5. Recommended: restrict the app to just this mailbox. `Mail.Read` as an application
   permission otherwise covers every mailbox in the tenant. In Exchange Online PowerShell:

   ```powershell
   Connect-ExchangeOnline
   New-ApplicationAccessPolicy -AppId <client id> -PolicyScopeGroupId dmarc-reports@example.com -AccessRight RestrictAccess -Description "DMARC analyzer: this mailbox only"
   Test-ApplicationAccessPolicy -AppId <client id> -Identity dmarc-reports@example.com
   ```

   The policy can take up to 30 minutes to apply. `PolicyScopeGroupId` can also be a
   mail-enabled security group if you want to allow several mailboxes.

That gives you the four values the app needs: tenant ID, client ID, the credential (a
client secret, or a certificate and its private key), and the mailbox address.

## Several mailboxes and tenants

Administrators add mailboxes under **Mailbox sync** in the app: a name, the mailbox
address, the tenant ID and client ID of an app registration in that mailbox's tenant, the
credential (**Client secret**, or **Certificate** with the PEM certificate, its private key
and the key's passphrase if it has one), and optionally a folder. Each mailbox is synced on
its own with its own cursor, a failure in one (expired secret or certificate, consent
revoked) does not stop the others, and every report remembers which mailbox it came from.
When more than one is configured a **Mailbox** dropdown joins the filter bar. The mailbox
table shows which credential each one uses and, for certificates, the thumbprint and expiry
date; a certificate within 30 days of expiry is highlighted.

The mailbox given through `GRAPH_*` and `DMARC_MAILBOX` still works and shows up as the
read-only **(env)** entry. Mailboxes added in the app are stored in `mailboxes.json` in
the data directory with their secrets or private keys, so keep that directory private.

## Run it

### Docker Compose

```bash
git clone https://github.com/spicy384/dmarc-report-analyzer.git
cd dmarc-report-analyzer
```

Create a `.env` file next to `docker-compose.yml` so the secret stays out of the compose
file:

```
GRAPH_TENANT_ID=00000000-0000-0000-0000-000000000000
GRAPH_CLIENT_ID=00000000-0000-0000-0000-000000000000
GRAPH_CLIENT_SECRET=the-secret-value
DMARC_MAILBOX=dmarc-reports@example.com
```

For a certificate instead of a secret, put the PEM files in a `certs/` folder next to the
compose file (it is mounted read-only at `/certs`) and point at them:

```
GRAPH_TENANT_ID=00000000-0000-0000-0000-000000000000
GRAPH_CLIENT_ID=00000000-0000-0000-0000-000000000000
GRAPH_CERT_FILE=/certs/graph-cert.pem
GRAPH_KEY_FILE=/certs/graph-key.pem
DMARC_MAILBOX=dmarc-reports@example.com
```

Then:

```bash
docker compose up -d
```

Open <http://localhost:3000> and create the first administrator. If no mailbox is
configured yet (no `GRAPH_*` variables and none added in the app), a four-step
walkthrough opens right after sign-in: what to collect from Entra, the app registration
and its credential (secret or certificate), the mailbox, then a connection test with a
plain-language reading of any failure and a button to run the first sync. **Skip for now**
puts it away; **Setup guide** under Mailbox sync reopens it at any time. Otherwise check
the **Mailbox sync** panel: **Test** confirms the token and the folder, **Sync all now**
pulls the reports. The first sync looks back `BACKFILL_DAYS` (90 by default); later runs continue
from the newest email seen, and a scheduled run happens every `SYNC_INTERVAL_MINUTES`.

The compose file publishes the port on loopback only, because the app serves plain HTTP.
For anything reachable from other machines put it behind HTTPS: `deploy/caddy` is a
ready-made setup with automatic Let's Encrypt certificates, and the section below covers
the app's own TLS.

### Without Docker

```bash
npm install
GRAPH_TENANT_ID=... GRAPH_CLIENT_ID=... GRAPH_CLIENT_SECRET=... DMARC_MAILBOX=... node server.js
```

Data lives in `./data` unless `DATA_DIR` says otherwise.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GRAPH_TENANT_ID` | | Directory (tenant) ID of the app registration |
| `GRAPH_CLIENT_ID` | | Application (client) ID |
| `GRAPH_CLIENT_SECRET` | | Client secret value (leave unset when using a certificate) |
| `GRAPH_CERT_FILE` | | Path to the certificate PEM; may hold the key too. Used instead of the secret |
| `GRAPH_KEY_FILE` | | Path to the private key PEM, when it is a separate file |
| `GRAPH_KEY_PASSPHRASE` | | Passphrase of the private key, if it is encrypted |
| `GRAPH_CERT_PEM`, `GRAPH_KEY_PEM` | | The same as inline PEM text, for setups that inject secrets as variables |
| `DMARC_MAILBOX` | | The mailbox receiving reports, as a UPN / email address |
| `DMARC_FOLDER` | `Inbox` | Folder to read. A display name, or a `Parent/Child` path |
| `SYNC_INTERVAL_MINUTES` | `60` | Scheduled sync interval. `0` turns it off; **Sync now** still works |
| `BACKFILL_DAYS` | `90` | How far back the very first sync looks |
| `RETENTION_MONTHS` | `0` (keep all) | Roll up reports older than this many months into daily totals |
| `GEOIP_CITY_DB`, `GEOIP_ASN_DB` | `<data>/geoip/GeoLite2-*.mmdb` | MaxMind database files, if you have them |
| `GEOIP_ONLINE` | `true` | Fall back to ip-api.com for IPs the files cannot answer |
| `PORT` | `3000` | Listening port |
| `PASSKEY_RP_ID`, `PASSKEY_ORIGIN` | from the request | Domain and origin passkeys are bound to, when a proxy hides the real ones |
| `DATA_DIR` | `./data` | Accounts, sessions, the SQLite database, generated TLS files |
| `TZ` | `UTC` | Timezone for the container |
| `COOKIE_SECURE` | `false` | Mark the session cookie Secure. Set `true` behind HTTPS |
| `TLS_ENABLED` | `false` | Serve HTTPS with a generated self-signed certificate |
| `TLS_HOSTS` | | Extra names/IPs for that certificate, comma separated |
| `TLS_CERT`, `TLS_KEY` | | Use your own certificate instead |
| `TRUST_PROXY_AUTH` | `false` | Accept the user from a reverse-proxy header (see below) |
| `PROXY_USER_HEADER` | `remote-user` | Which header carries the username |

Nothing in the mailbox is changed: the app only reads. It remembers which emails it has
ingested by their Graph message ID, and a report delivered twice (same reporter, report ID
and domain) is stored once.

### Retention

Everything is kept by default. Set `RETENTION_MONTHS` to roll reports older than that
into daily totals: their individual records and stored XML are removed, the report rows
stay (marked as rolled up), and totals, the chart and the weekly view still cover the
full history. Sources, records, search, the CSV export and XML downloads only cover
retained data, and the overview says so when the selected period reaches further back.
The pass runs 30 seconds after start and then daily.

### Country and network of source IPs

Every source IP is looked up for country, city and network (ASN) after each sync, shown
in the **Network** column and searchable. Two sources, files preferred:

- **MaxMind GeoLite2 files**, read locally so no IP leaves your network. Create a free
  MaxMind account, download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`, and put them in
  `geoip/` inside the data directory (`/data/geoip` in the container, or point
  `GEOIP_CITY_DB` and `GEOIP_ASN_DB` at them). Restart, or use **Re-run GeoIP lookups**
  under Mailbox sync to resolve everything again with the files.
- **ip-api.com**, used for whatever the files cannot answer, or for everything when there
  are no files. It is queried over plain HTTP in batches of 100, at most 15 requests a
  minute, and its free tier is for non-commercial use; every unknown source IP is sent to
  it. Set `GEOIP_ONLINE=false` to never use it.

### What gets ingested

Every email with attachments in the folder. Each attachment is inspected by content, not by
name or type, since senders mislabel them: `.zip` (one or more XML files inside), `.xml.gz`
and bare `.xml` are all handled, as is a zip inside a gzip. Attachments that are not DMARC
aggregate reports (logos, signatures, calendar items) are ignored; an email with none is
recorded as "no report" and not looked at again. An email whose report is malformed is
listed under **Messages that could not be read** with the reason.

## HTTPS and reverse proxies

The app serves plain HTTP by default. Three options, in order of preference:

1. **A reverse proxy on the same host** (Caddy, Traefik, Nginx Proxy Manager) on a shared
   Docker network, with the app publishing no ports at all. `deploy/caddy` does exactly
   this with automatic certificates. Set `COOKIE_SECURE=true`.
2. **A proxy on another host.** Set `TLS_ENABLED=true` and list the address the proxy
   connects to in `TLS_HOSTS`, so the hop between them is encrypted with a self-signed
   certificate. Proxies do not verify upstream certificates by default.
3. **Your own certificate** via `TLS_CERT`/`TLS_KEY`, mounted read-only.

### Behind an authentication proxy

If Authelia, Authentik or oauth2-proxy already protects the app, set
`TRUST_PROXY_AUTH=true` and the app trusts the username in `PROXY_USER_HEADER`. The user
must still exist locally (create them under **Users**); the proxy asserts who they are, not
whether they may use the app. Only do this when the proxy strips that header from client
requests and the app is reachable through nothing else, because otherwise anyone who can
reach the port can be anyone.

## Data

Everything is under `DATA_DIR` (`/data` in the container):

- `dmarc.sqlite` - reports, records, messages seen, reverse-DNS cache, sync history. The
  original XML of every report is kept (gzipped) so it can be downloaded or re-parsed.
- `users.json`, `sessions.json` - accounts (scrypt password hashes, TOTP secrets, hashed
  recovery codes) and sessions.
- `tls/` - the generated certificate when `TLS_ENABLED=true`.

Back up the directory; treat it as sensitive.

## Tests

```bash
node test/run-all.js
```

Parser (containers and XML shapes from the samples in `examples/`), storage and
aggregation, the ingest job against a mock Graph server (paging, throttling, transient and
fatal failures, deduplication, reverse DNS), the HTTP API, and the accounts/sessions/TOTP
flow against the real server.

## Ideas not built

- Alerting by email or webhook (alerts are in-app only).
- Full ASN-level roll-ups of sources (each IP is shown with its network; there is no
  per-network view).
