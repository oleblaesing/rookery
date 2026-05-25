# Operator runbook

Every dispatcher subcommand and the common `psql` queries you'll actually use.
The full dispatcher reference is `./rookery help` and `./rookery help <subcommand>`.

## Dispatcher subcommands

### Bootstrap and lifecycle

```sh
./rookery init [--domain X] [--email Y] [--name N] [--user U] [--no-prompt] [--clamav]
```
Generate `rookery.toml`, `.env`, `Caddyfile`, and `./rookery.service` in the
checkout directory. Idempotent — safe to re-run after a `git pull` that adds new
generated files. Never overwrites existing files, except that `--clamav` always
regenerates `./rookery.service` with `--profile clamav` in `ExecStart` (enables
opt-in ClamAV virus scanning; requires ≥4 GB RAM).

To enable ClamAV on an existing installation:
```sh
./rookery init --clamav
sudo ./rookery install
sudo systemctl restart rookery
```

```sh
sudo ./rookery install
```
Copy `./rookery.service` into `/etc/systemd/system/` and run
`systemctl daemon-reload`. Run once per host. Does NOT enable or start the unit.

```sh
sudo systemctl enable --now rookery
```
Standard systemd. Enables autostart and starts immediately.

```sh
./rookery start [--prod]
```
Bring the stack up manually. `--prod` enables Caddy (TLS on 80/443). The systemd
unit always passes `--prod -d`. Without `--prod`, Caddy is not started — hit
port 8080 directly in dev.

```sh
./rookery stop
./rookery restart [--prod]
./rookery update          # git pull --ff-only && compose build; does NOT restart
```

### Invites

```sh
./rookery invite create          # non-expiring invite URL to stdout
./rookery invite create 7        # expires in 7 days
```

### User management

```sh
./rookery user suspend alice@rookery.example
```
Sets `suspended_at = now()` on the user row. Suspended accounts can't send or
receive. Inbound SMTP responds with `550 Account suspended`; outbound attempts
fail. Reversible.

```sh
./rookery user unsuspend alice@rookery.example
```
Clears `suspended_at`. Account is immediately active again.

```sh
./rookery user delete alice@rookery.example ["reason"]
```
Hard-deletes the user and ALL their mail via CASCADE. Requires typing the address
to confirm. Irreversible. Message blobs on disk are orphaned (a future blob-gc
pass will clean them). Optional reason string is logged to stderr only — there
is no audit table yet (Phase 6).

### Statistics

```sh
./rookery stats print
```
Quick summary: active/suspended users, messages received in the last 24 hours,
outbound queue depth, delivered/bounced counts.

### Master key rotation

```sh
./rookery master-key rotate
```
Re-encrypts all DKIM private keys in the database under a new master key, then
updates `ROOKERY_MASTER_KEY` in `.env`. The stack must be running. Prompts for
confirmation. After completion: restart the stack and back up `.env` immediately.

See [Rotating the master key](#rotating-the-master-key) below.

### DNS verification

```sh
./rookery check-dns [--resolver 9.9.9.9]
```
Checks every required DNS record against live DNS and shows green/red per record.
When the stack is running, also shows the exact values you should have published
(reads from the database). `--resolver` overrides the system resolver — useful to
bypass local caching during propagation.

### Development

```sh
./rookery send-mail alice@localhost
./rookery send-mail --encrypted --fetch-key alice@localhost
./rookery psql
./rookery logs [service]
./rookery test
./rookery vet
```

### Escape hatches

```sh
./rookery exec rspamd rspamc stat      # rspamd statistics
./rookery compose logs --since 1h      # raw docker compose pass-through
```

---

## Common psql queries

Access via `./rookery psql` (reads the password from `.env` automatically).

### Users

```sql
-- List all users with their primary address and quota
SELECT a.address, u.quota_bytes, u.used_bytes,
       u.suspended_at IS NOT NULL AS suspended,
       u.created_at
FROM   users u
JOIN   addresses a ON a.id = u.primary_address_id
ORDER  BY u.created_at;

-- Change a user's quota (example: 10 GiB)
UPDATE users SET quota_bytes = 10737418240
WHERE id = (
    SELECT user_id FROM addresses WHERE address = 'alice@rookery.example'
);

-- Find a user's ID by address
SELECT u.id, a.address, u.suspended_at
FROM   users u
JOIN   addresses a ON a.user_id = u.id
WHERE  a.address = 'alice@rookery.example';
```

### Messages

```sql
-- Count messages by folder for a user
SELECT folder, count(*)
FROM   messages
WHERE  user_id = (
    SELECT user_id FROM addresses WHERE address = 'alice@rookery.example'
)
GROUP  BY folder;

-- Find a message by subject
SELECT id, from_address, subject, received_at, security_state
FROM   messages
WHERE  subject ILIKE '%hello%'
ORDER  BY received_at DESC
LIMIT 10;

-- Disk usage: largest blobs
SELECT blob_sha256, size_bytes
FROM   messages
ORDER  BY size_bytes DESC
LIMIT 10;
```

### Outbound queue

```sql
-- Current queue state
SELECT status, count(*) FROM outbound_queue GROUP BY status;

-- Stuck messages (failed, next retry in the past)
SELECT id, recipient, attempts, last_error, next_retry_at
FROM   outbound_queue
WHERE  status = 'failed'
  AND  next_retry_at < now()
ORDER  BY created_at;

-- Recent bounces with sender info
SELECT a.address AS sender, q.recipient, q.last_error, q.created_at
FROM   outbound_queue q
JOIN   messages m ON m.id = q.message_id
JOIN   users u ON u.id = m.user_id
JOIN   addresses a ON a.id = u.primary_address_id
WHERE  q.status = 'bounced'
ORDER  BY q.created_at DESC
LIMIT 20;
```

### Sessions

```sql
-- Active sessions (by user)
SELECT a.address, count(*) AS sessions, max(s.last_seen) AS last_active
FROM   sessions s
JOIN   users u ON u.id = s.user_id
JOIN   addresses a ON a.id = u.primary_address_id
WHERE  s.last_seen > now() - interval '7 days'
GROUP  BY a.address
ORDER  BY last_active DESC;

-- Expire all sessions for a user (force re-login)
DELETE FROM sessions
WHERE user_id = (
    SELECT user_id FROM addresses WHERE address = 'alice@rookery.example'
);
```

### Invites

```sql
-- List pending (unused, non-expired) invites
SELECT id, token, expires_at, created_at
FROM   invites
WHERE  used_at IS NULL
  AND  (expires_at IS NULL OR expires_at > now());

-- Revoke an invite
DELETE FROM invites WHERE token = '<token>';
```

### Domains

```sql
-- All managed domains with verification status
SELECT domain, is_primary, verified_at IS NOT NULL AS verified,
       mta_sts_id, wkd_active, created_at
FROM   domains
ORDER  BY is_primary DESC, created_at;
```

---

## Rotating the master key

The master key (`ROOKERY_MASTER_KEY` in `.env`) encrypts DKIM private keys at
rest. Rotate it when:
- You suspect the key has been compromised.
- You're following a scheduled rotation policy.
- You're migrating to a new server and want a fresh key.

**Before rotating:** take a database snapshot (via your VPS provider's backup
feature, or `pg_dump` via `./rookery psql`).

```sh
./rookery master-key rotate
```

The command:
1. Generates a new random master key.
2. Re-encrypts all DKIM private keys in the database under the new key.
3. Atomically updates `ROOKERY_MASTER_KEY` in `.env`.
4. Tells you to restart and back up.

After rotation:

```sh
sudo systemctl restart rookery
# then immediately:
cp .env .env.backup-$(date +%Y%m%d)
```

**If rotation fails mid-way:** the command is atomic — it either re-encrypts all
keys or none. If it fails before updating `.env`, the database still has the old
encryption and `.env` still has the old key. Re-run after fixing the underlying
error (usually: stack not running, or out of disk space).

---

## Per-user outbound rate limits

Defaults (configurable in `rookery.toml`):
- 200 messages per hour per user
- 1000 messages per day per user
- 5000 messages per hour to any single destination domain

A user who hits the hourly limit gets an error in the compose UI; their queued
outbound messages are not dropped. Limits reset on the rolling window. If a
legitimate user needs higher limits, adjust in `rookery.toml` and restart.

---

## Trash retention

Messages deleted by users move to Trash. Trash is purged after 30 days by
default (configurable: `trash_retention_days` in `rookery.toml`). Set to `0`
for immediate hard delete on trash. The purge worker runs once per hour.

---

## ClamAV (opt-in virus scanning)

Not running by default. See [deployment.md](deployment.md) for how to enable.
When enabled: virus-infected messages are rejected at SMTP time with a 5xx code.
The sender receives a delivery failure notification.
