# Troubleshooting

Common failure modes and how to diagnose them.

## Mail isn't arriving (inbound)

### Check that port 25 is open

Many VPS providers block outbound port 25 by default. Less common, but some also
block inbound 25. Test from a machine outside your provider:

```sh
nc -zv rookery.example 25
# or
telnet rookery.example 25
```

If the connection is refused, open port 25 in your provider's firewall/security
group. If it times out, your provider may be blocking it network-wide — contact
support.

### Check DNS propagation

```sh
./rookery check-dns --resolver 9.9.9.9
```

Missing MX record means no mail can arrive. Missing SPF/DKIM/DMARC means
inbound mail may arrive but outbound mail to other servers won't.

### Check the logs

```sh
./rookery logs
./rookery logs rookery
```

Look for `smtp:` log lines. A `550 No such user` suggests the recipient address
doesn't exist on this instance.

---

## Outbound mail goes to spam

This is the most common problem for new instances. **There is no quick fix.**
See [spam-runbook.md](spam-runbook.md) for the full honest picture.

Short version:
1. Run `./rookery check-dns` — every record must be green.
2. Check `mail-tester.com` — paste a send address, send a test message, read the
   report. Fix each item it calls out.
3. Wait. New IP addresses are not trusted by Gmail and Outlook. It takes weeks of
   legitimate mail volume for reputation to build.

---

## Caddy ACME loop (certificate not provisioning)

Symptoms: the web UI shows an HTTP error instead of a certificate; Caddy logs
show repeated ACME attempts.

**Port 80 must be open and reachable.** Caddy uses HTTP-01 for ACME challenges.
Check that:

1. Port 80 is open in your firewall/security group.
2. `curl http://rookery.example` reaches the server from outside (not just from
   localhost).
3. DNS for `rookery.example`, `openpgpkey.rookery.example`, and
   `mta-sts.rookery.example` all resolve to your server's IP.

If you've burned Let's Encrypt rate limits (5 failed certificate orders for the
same hostname in a rolling week):

```sh
./rookery logs caddy | grep -i acme
```

Look for "too many certificates" or "rate limit" messages. If rate-limited, wait.
In the meantime, you can run with `--staging` in the Caddyfile to test without
hitting production LE — change `tls { ... }` blocks to use the staging CA.

---

## Login fails / challenge/response error

rookery's login is PGP challenge/response. The server issues a nonce; your
browser signs it with your private key; the server verifies.

Common causes:
- **Wrong recovery file.** Make sure you're using the file generated when you
  registered on *this* instance, not an old one from a different instance or an
  old key rotation.
- **Wrong passphrase.** The passphrase encrypts the recovery file. If you can't
  unlock the file, you can't log in. There is no server-side reset.
- **Expired or revoked session.** Sessions expire after 7 days of inactivity by
  default (configurable in `rookery.toml`). Log in again.

If you're locked out and you're the operator: there's nothing you can do server-
side. The server holds no passphrase hash and no private key. The user must have
their recovery file and passphrase.

---

## Database connection errors at startup

```
failed to open store ... connection refused
```

Postgres didn't start or isn't healthy yet. Check:

```sh
./rookery logs postgres
./rookery ps
```

If postgres is in a restart loop:

```sh
./rookery exec postgres pg_isready -U rookery -d rookery
```

The most common cause is a missing or wrong `ROOKERY_DB_PASSWORD` in `.env`. Run
`./rookery init` to regenerate `.env` if the file is missing or corrupted.

---

## Stack won't start: `.env` or `rookery.toml` missing

```
rookery: error: .env or rookery.toml missing — run './rookery init' first
```

Run `./rookery init`. It's idempotent and won't overwrite existing files.

---

## rspamd rejecting legitimate mail

rspamd uses the heuristics and thresholds that ship with it. The default `reject`
threshold is 15 — relatively high to avoid false positives. If legitimate mail is
being rejected:

1. Check the `X-Spam-Status` header in the rejected message (or look at rspamd
   logs via `./rookery logs rspamd`).
2. Identify which rules are triggering. Common false-positive causes:
   - Sender's IP is on a public RBL (unlikely for a legitimate sender but happens).
   - Message has no DKIM signature (ask the sender to configure DKIM).
   - Message passes through a forwarding relay that breaks DKIM.
3. Tune rspamd by adding exceptions in `./rspamd/local.d/` and restarting:
   ```sh
   ./rookery restart
   ```

See `./rookery exec rspamd rspamc stat` for rspamd statistics.

---

## Master key / DKIM key issues

If the master key is wrong or missing, DKIM signing fails. Symptoms:

```sh
./rookery logs | grep "dkim:"
```

Look for `dkim: decrypt key: ...` errors. This means `ROOKERY_MASTER_KEY` in
`.env` doesn't match the key that encrypted the DKIM private keys in the database.

Cause: either `.env` was regenerated (which generates a new master key, breaking
existing encrypted data), or the master key was rotated and the `.env` wasn't
updated.

Resolution: restore `.env` from your backup with the correct `ROOKERY_MASTER_KEY`.
If you have no backup and the old master key is truly lost, you must regenerate
DKIM keys (`DELETE FROM dkim_keys` in `./rookery psql`; they'll be regenerated
on next startup) and republish the DKIM TXT records in DNS.

---

## "Mailbox full" — user can't receive mail

```sh
./rookery psql
```

```sql
SELECT primary_address_id, quota_bytes, used_bytes
FROM users;
```

Increase the quota for a specific user:

```sql
UPDATE users SET quota_bytes = 10737418240  -- 10 GiB
WHERE id = (
    SELECT user_id FROM addresses WHERE address = 'alice@rookery.example'
);
```

---

## Container won't build

```sh
./rookery compose build --no-cache rookery
```

If the build fails on the Go compile step, check `go.sum` and `go.mod` are
committed and up to date. If it fails on the esbuild step (JS crypto module),
make sure `web/crypto/` contains the source files.

---

## Checking what version is running

```sh
./rookery exec rookery /usr/local/bin/rookery-server healthcheck
./rookery logs | grep "rookery starting"
```

The startup log line includes the git revision hash embedded at build time.
