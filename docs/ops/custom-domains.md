# Custom domains

Custom domains let users receive mail at their own domain (e.g. `alice@alice.com`)
through a rookery instance, without running their own server. Phase 4 shipped this.

## User flow

Users add custom domains through the **Settings → Custom Domains** page in the
web UI. The flow:

1. Enter the domain name.
2. The page generates the full set of DNS records to publish.
3. Publish the records in your domain registrar's DNS panel.
4. Click "Verify DNS" — the server checks each record.
5. Once all records are verified, the domain is active.

DNS records required (see [dns.md](dns.md) for the full reference):

- `MX` pointing to the primary instance domain
- `SPF TXT` authorising the instance to send for your domain
- `CNAME` for each DKIM selector (`rookery-ed25519`, `rookery-rsa`)
- `TXT` challenge record for ownership verification
- `CNAME` for `openpgpkey.<yourdomain>` (WKD key publishing)
- `CNAME` for `mta-sts.<yourdomain>` (strict transport security)
- `TXT` at `_mta-sts.<yourdomain>` (MTA-STS policy pointer)
- `TXT` at `_dmarc.<yourdomain>` (DMARC policy)
- `TXT` at `_smtp._tls.<yourdomain>` (TLS-RPT; recommended)

The web UI shows the exact values for each record and lets you track verification
progress per record.

## Operator notes

**Custom domains are fully user self-serve.** There is no `rookery domain add`
subcommand. Users complete the flow in the web UI themselves.

**Pre-registering a domain for a user** (e.g. before inviting them) is possible
via `./rookery psql` with a direct `INSERT` into the `domains` table, but this
is an advanced operation and the UI flow is the supported path.

**DNS drift detection** runs hourly. If a user's registrar silently drops a
required record (it happens), the server detects the drift and surfaces it in
the Settings → Custom Domains page.

**Per-domain MTA-STS** starts in `testing` mode for the first 48 hours after
a domain is verified, then switches to `enforce`. The status is visible in the
UI and in `./rookery logs`.

## The portability argument

A user on a custom domain can move to a different rookery instance by:
1. Exporting their mailbox from the current instance (Phase 6).
2. Importing it on the new instance.
3. Changing their MX and DKIM CNAME records to point at the new instance.

Their email address is unchanged. Their private key was never on the old
instance — it lives in their recovery file. This is the "deliberately replaceable"
property that makes custom domains the killer feature of the project.

---

*This page documents what's shipped. Further guide content (self-serve UI
screenshots, troubleshooting for common DNS provider UIs) will be added as
Phase 4 stabilises.*
