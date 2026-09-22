# Deployment examples

Pick the one that matches where your reverse proxy lives. Each directory is a
self-contained Compose project with its own `.env.example`.

| Setup | Use when | HTTPS handled by |
|---|---|---|
| [`../docker-compose.yml`](../docker-compose.yml) | Simplest. You reach it on the server itself, or over an SSH tunnel | Nothing - plain HTTP on loopback |
| [`caddy/`](caddy) | You have a domain and this host can be reached on 80/443 | Caddy, automatic Let's Encrypt |

Both run the same image. The differences are only in what is exposed and who
terminates TLS.

---

## caddy/ - one host, automatic certificates

Caddy gets a Let's Encrypt certificate, renews it, and proxies to the app over an
internal Docker network. **The app publishes no ports**, so the only route in is
through Caddy over HTTPS.

```bash
cd deploy/caddy
cp .env.example .env      # set DMARC_DOMAIN, ACME_EMAIL and the GRAPH_*/DMARC_* mailbox settings
docker compose up -d
```

Needs a real domain pointing at this host and inbound TCP 80 and 443. Caddy uses
80 for the ACME challenge and for redirecting HTTP to HTTPS.

Watch the first start - certificate issuance takes a few seconds:

```bash
docker compose logs -f caddy
```

Because the proxy and the app share a host, the hop between them never touches the
network, so the app runs plain HTTP internally and `TLS_ENABLED` stays off.

**Keep the `caddy_data` volume.** It holds the certificates and the ACME account
key. Deleting it forces re-issuance, and Let's Encrypt allows only 5 identical
certificates per week.

If this host is not reachable from the internet, Let's Encrypt cannot validate the
domain. The `Caddyfile` documents two alternatives: `tls internal` (Caddy's own CA,
real HTTPS but browsers warn until you trust its root), or DNS-01 validation with a
Caddy image built with your DNS provider's plugin.

---

## Supplying your own certificate

Either of these can use a real certificate instead of a generated one. Obtain it
however you like - certbot with DNS-01 needs no inbound access - then:

```yaml
environment:
  TLS_CERT: /certs/fullchain.pem
  TLS_KEY: /certs/privkey.pem
volumes:
  - /etc/letsencrypt/live/dmarc.example.com:/certs:ro
```

`TLS_CERT`/`TLS_KEY` take precedence over `TLS_ENABLED`. Certificates are read only
at startup, so restart the container after a renewal.
