# Spam runbook

Honest guidance on what rookery does about spam, what it can't do, and what you
can do when things go wrong. See also PLAN.md §9 and §10.

## What rookery ships

**rspamd** handles inbound spam filtering: header heuristics, RBL queries,
SPF/DKIM/DMARC alignment checks, URL reputation, and a pre-trained neural
network module. This runs out of the box with no tuning required.

**Redis** backs rspamd's rate limits, fuzzy hashes, and learned-data stores.

**ClamAV** is opt-in (adds ~1 GB RAM). See [deployment.md](deployment.md) for
how to enable it.

Stock rspamd defaults:
- Messages scoring ≥ 15 are **rejected** at SMTP time (never stored).
- Messages scoring 6–15 are tagged `add header` — delivered with `X-Spam-*`
  headers visible in the message detail view.
- Messages scoring below 6 are delivered normally.

These thresholds are well-calibrated for general use. You probably don't need to
change them.

## What rookery can't do: the IP reputation problem

**Here is the honest reality of self-hosted email in 2025:**

Your new VPS IP address has no reputation with Gmail, Outlook, or Yahoo. It
doesn't matter how perfect your DNS configuration is. Major providers filter
based on IP reputation built up over weeks and months of legitimate mail volume.
A fresh address from a consumer VPS range (Hetzner, DigitalOcean, Vultr) will
often land in spam at Gmail for the first 4–8 weeks, sometimes longer.

This is not something rookery can fix. It is the central operational challenge
of self-hosted email. PLAN.md §9.1 and §10 document this honestly:

> Deliverability — reputation score: not an NFR, on purpose. The headline
> mail-tester.com score and inbox-placement at Gmail/Outlook depend on the IP
> reputation of the VPS provider's range, which we do not control.

### What you can do

1. **Check mail-tester.com.** Send a test message to a `mail-tester.com`
   address. A score of 10/10 means your configuration is correct. It does not
   mean your mail will land in inboxes at Gmail — only that your technical setup
   is right. Fix everything mail-tester flags before worrying about inbox placement.

2. **Start with low volume.** Send a few messages per day to known contacts who
   use Gmail. Ask them to mark your mail as "not spam" when it lands in the spam
   folder. This builds reputation gradually.

3. **Use a smarthost relay.** Services like AWS SES, Postmark, or Mailgun charge
   per message but send from IPs with pre-built reputation. Gmail-bound mail
   reliably lands in inboxes from day one. Configure the `[smtp.smarthost]` block
   in `rookery.toml` (host/port/username, `require_tls = true`, `auth = true`) and
   set `ROOKERY_SMTP_RELAY_PASSWORD` in `.env`, then restart. rookery DKIM-signs
   every message locally before relaying it over an authenticated TLS submission
   session. See ADR-0030 for the design.

4. **Use a relay rookery.** Another rookery instance with an established IP
   reputation can relay your outbound mail. To rookery this is identical to a
   commercial relay — the same `[smtp.smarthost]` block, just pointed at the other
   instance's hostname with the relay-client credentials it issued you. Like a
   commercial relay but operated by a person you know. (Acting *as* a relay rookery
   for others is the second half of the feature — see ADR-0030 Phase B.)

5. **Provision a clean IP.** Some providers (especially in Europe — Hetzner,
   Netcup, certain OVH products) have reputation-clean ranges. A dedicated IP
   with proper PTR helps significantly.

6. **Register with postmaster tools.** Google Postmaster Tools
   (`postmaster.google.com`) lets you track your domain's reputation and
   deliverability metrics over time. Register your sending domain.

### What doesn't help

- A perfect `mail-tester.com` score alone. Necessary but not sufficient.
- Changing VPS providers repeatedly ("fresh IP hopping"). Each fresh IP starts
  at zero. Persistence and volume build reputation.
- Getting upset at PLAN.md for being honest about this.

## Acting as a relay rookery

The flip side of "use a relay rookery" is *being* one: letting another operator
you trust send their outbound mail through your instance, so it inherits your
IP's reputation. This is the second half of the smarthost feature (ADR-0030,
Phase B). It is **off by default** and you should turn it on only with eyes open.

**The honest risk (PLAN §11.10):** when you relay for a downstream, your IP
carries their mail. If they send spam — deliberately, or because their instance
was compromised — Gmail and Outlook blame *your* IP, not theirs. Unlike a
commercial relay you have no abuse team, no KYC, and no lawyers. **Only relay for
operators you actually know and trust.** Relay trust here is bilateral and
out-of-band: there is no directory, no auto-discovery, no federation. You hand a
credential to one person at a time, exactly like any inter-MTA relay agreement.

**Turn it on:**

1. You must be running the prod profile (Caddy), because the submission listener
   reuses the TLS certificate Caddy provisions for your domain. There is no
   second ACME client.
2. **Let rookery read Caddy's certs.** By default Caddy runs as root and writes
   its certificates as root-owned `0600` files, but the rookery process runs as
   the distroless nonroot UID `65532` and cannot read them — the submission
   listener will fail to start with "no readable certificate". Fix it once by
   running Caddy under the same UID (the Caddy binary carries
   `cap_net_bind_service`, so it still binds 80/443 as a non-root user):

   ```sh
   ./rookery stop

   # Point the caddy container at the rookery container's UID/GID (65532).
   printf 'CADDY_UID=65532\nCADDY_GID=65532\n' >> .env

   # Hand Caddy's existing data to that UID (it was created root-owned).
   proj=$(docker compose -f compose.yaml config | awk '/^name:/{print $2; exit}')
   docker run --rm -v "${proj}_caddy-data:/data" -v "${proj}_caddy-config:/config" \
     docker.io/library/alpine:latest chown -R 65532:65532 /data /config

   ./rookery start --prod
   ```

   To revert, remove the `CADDY_UID`/`CADDY_GID` lines from `.env` and restart;
   root can still read the now-UID-owned files, so nothing breaks.
3. Set `submission_enabled = true` under `[smtp]` in `rookery.toml` and restart.
   This starts authenticated SMTP submission listeners on ports 465 (implicit
   TLS) and 587 (STARTTLS). AUTH is offered only over TLS; an unauthenticated
   session can never relay (this is never an open relay).

**Issue and manage downstream credentials** (the stack must be running):

```sh
# Issue a credential. The secret is printed ONCE and is not recoverable — only a
# bcrypt hash is stored. The command also prints a ready-to-paste [smtp.smarthost]
# block for the downstream operator's rookery.toml.
./rookery relay-client create --label "alice's instance"

# See who has credentials, whether they're enabled, their rate cap, last use.
./rookery relay-client list

# Disable a client — the only abuse remedy in v1. Takes effect on their next
# authentication; revoke immediately if a downstream misbehaves.
./rookery relay-client revoke relay-ab12cd34ef56
```

Each client has a per-hour rate cap (`rate_per_hour`, default 200); over-limit
submissions are temp-failed (4xx) so the downstream's own queue retries. Adjust a
client's cap directly in the `relay_clients` table via `./rookery psql` if needed.

**What you relay is opaque transport.** rookery does **not** re-sign relayed mail
— the downstream already DKIM-signed it, and that signature is what receivers
verify. Your instance only forwards the bytes. Relayed mail rides the same
outbound queue, retry, and bounce machinery as locally-composed mail.

> **v1 limitation:** if onward delivery of a relayed message permanently fails,
> rookery logs and drops it rather than generating a DSN back to the original
> sender (it has no local mailbox to deposit one in). The downstream already
> received a 250 at submission time. Bounce-to-sender for relayed mail is out of
> scope for v1 (ADR-0030).

The `relay_clients` table and the relayed queue rows live in Postgres, so they
are captured by `./rookery backup` with no extra steps.

## Inbound spam that gets through

If spam lands in your inbox (score below reject threshold):

1. Check the `X-Spam-Status` header in the message detail view. It shows the
   rspamd score and which rules fired.

2. rspamd has no per-user Bayesian training in v1 (that's Phase 8). Stock rule
   tuning is the only lever.

3. To raise sensitivity (more aggressive filtering, more false positives):
   Edit `./rspamd/local.d/` — for example, lower the `add header` or `reject`
   thresholds:
   ```
   # rspamd/local.d/actions.conf
   actions {
     reject = 12;         # default 15
     add_header = 5;      # default 6
   }
   ```
   Then restart: `./rookery restart`.

4. Block a specific sender domain by IP or envelope:
   ```
   # rspamd/local.d/multimap.conf
   BLOCKED_SENDER {
     type = "from";
     map = "/etc/rspamd/local.d/blocked_senders.map";
     score = 20;  # above reject threshold
   }
   ```
   Create `rspamd/local.d/blocked_senders.map` with one address/domain per line.

## Legitimate mail being rejected (false positives)

If a legitimate sender's mail is being rejected:

1. Ask the sender for the rejection message — it will say `Message rejected as spam`
   with an SMTP 5xx code.

2. Check rspamd logs: `./rookery logs rspamd`

3. Whitelist the sender:
   ```
   # rspamd/local.d/multimap.conf
   TRUSTED_SENDER {
     type = "from";
     map = "/etc/rspamd/local.d/trusted_senders.map";
     score = -10;
   }
   ```
   Add sender addresses or domains to `rspamd/local.d/trusted_senders.map`.

4. Restart: `./rookery restart`

## Outbound spam (compromised account or abuse)

rookery enforces per-user outbound rate limits (200 messages/hour, 1000/day by
default). An account generating unusual volume hits these limits and subsequent
sends fail.

Monitor for abuse:

```sh
./rookery stats print
```

High bounce count or high sent-24h volume relative to your user count is a signal.
Dig deeper via `./rookery psql`:

```sql
-- Per-user outbound volume in the last 24 hours
SELECT a.address, count(*) as sent
FROM   outbound_queue q
JOIN   messages m ON m.id = q.message_id
JOIN   users u ON u.id = m.user_id
JOIN   addresses a ON a.id = u.primary_address_id
WHERE  q.created_at > now() - interval '24 hours'
GROUP  BY a.address
ORDER  BY sent DESC;

-- Recent bounces
SELECT a.address, q.recipient, q.last_error, q.created_at
FROM   outbound_queue q
JOIN   messages m ON m.id = q.message_id
JOIN   users u ON u.id = m.user_id
JOIN   addresses a ON a.id = u.primary_address_id
WHERE  q.status = 'bounced'
ORDER  BY q.created_at DESC
LIMIT 20;
```

If a user is sending spam, suspend them immediately:

```sh
./rookery user suspend user@rookery.example
```

Then investigate. If the account is clearly abused, delete it:

```sh
./rookery user delete user@rookery.example "spam abuse"
```

## rspamd admin access

rspamd's web UI and `rspamc` CLI are available via the escape hatch:

```sh
./rookery exec rspamd rspamc stat
./rookery exec rspamd rspamc fuzzy_stat
```

The rspamd web UI listens on port 11334 inside the container but is not exposed
to the host by default. To access it temporarily (don't leave this open):

```sh
./rookery compose port rspamd 11334
```

Add a `ports:` entry to the `rspamd` service in `compose.yaml` temporarily, or
use SSH port forwarding from your local machine.
