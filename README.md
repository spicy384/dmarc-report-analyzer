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
a `Get-MessageTrace` command (last 10 days, with an exact `FromIP` filter), a
`Start-HistoricalSearch` command (up to 90 days, emails a CSV), a Purview content-search
KQL string, and the local-time range to type into the admin center's message trace. A trace only sees mail that passed
through your tenant, so it finds outbound mail your Microsoft 365 sent and inbound mail it
received; mail sent from elsewhere straight to another provider never touched Exchange
Online.

**Export**: every record in the selected period as CSV, honouring the search and filters.

**Mailbox sync**: sync on a schedule or on demand, with live progress, a run history, and a
list of emails whose attachments could not be read. Emails already ingested are skipped, so
re-running is cheap; a backfill option re-scans from any date.

### A note on "times"

Aggregate (`rua=`) reports cover a window, usually one UTC day, and give counts per source
IP. They do **not** contain a timestamp for each message. The times you see here are the
report window and when the report email arrived. Only forensic (`ruf=`) reports carry
per-message timestamps, and almost no large provider sends those any more; they are not
parsed yet.

### Accounts

Sign-in with per-user accounts, optional TOTP two-factor and single-use recovery codes.
Administrators manage accounts and can test the mailbox connection, users can start a
sync, viewers can only look. It can also run behind an authentication reverse proxy
(Authelia, Authentik, oauth2-proxy) using the `TRUST_PROXY_AUTH` option.

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
4. **Certificates & secrets** → **New client secret**. Copy the **Value** immediately; it
   is shown once. Note the expiry and put a reminder in your calendar.
5. Recommended: restrict the app to just this mailbox. `Mail.Read` as an application
   permission otherwise covers every mailbox in the tenant. In Exchange Online PowerShell:

   ```powershell
   Connect-ExchangeOnline
   New-ApplicationAccessPolicy -AppId <client id> -PolicyScopeGroupId dmarc-reports@example.com -AccessRight RestrictAccess -Description "DMARC analyzer: this mailbox only"
   Test-ApplicationAccessPolicy -AppId <client id> -Identity dmarc-reports@example.com
   ```

   The policy can take up to 30 minutes to apply. `PolicyScopeGroupId` can also be a
   mail-enabled security group if you want to allow several mailboxes.

That gives you the four values the app needs: tenant ID, client ID, client secret, and the
mailbox address.

## Several mailboxes and tenants

Administrators add mailboxes under **Mailbox sync** in the app: a name, the mailbox
address, the tenant ID, client ID and client secret of an app registration in that
mailbox's tenant, and optionally a folder. Each mailbox is synced on its own with its own
cursor, a failure in one (expired secret, consent revoked) does not stop the others, and
every report remembers which mailbox it came from. When more than one is configured a
**Mailbox** dropdown joins the filter bar.

The mailbox given through `GRAPH_*` and `DMARC_MAILBOX` still works and shows up as the
read-only **(env)** entry. Mailboxes added in the app are stored in `mailboxes.json` in
the data directory with their client secrets, so keep that directory private.

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

Then:

```bash
docker compose up -d
```

Open <http://localhost:3000>, create the first administrator, and check the **Mailbox
sync** panel: **Test connection** confirms the token and the folder, **Sync now** pulls
the reports. The first sync looks back `BACKFILL_DAYS` (90 by default); later runs continue
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
| `GRAPH_CLIENT_SECRET` | | Client secret value |
| `DMARC_MAILBOX` | | The mailbox receiving reports, as a UPN / email address |
| `DMARC_FOLDER` | `Inbox` | Folder to read. A display name, or a `Parent/Child` path |
| `SYNC_INTERVAL_MINUTES` | `60` | Scheduled sync interval. `0` turns it off; **Sync now** still works |
| `BACKFILL_DAYS` | `90` | How far back the very first sync looks |
| `PORT` | `3000` | Listening port |
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

## Not yet

- Forensic (`ruf=`) reports.
- GeoIP / ASN lookup of source IPs.
- Alerts when a new failing source appears.
