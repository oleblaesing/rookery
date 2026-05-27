# Deployment guide

This guide walks a competent Linux user through standing up a rookery instance
from scratch. **Target: under 30 minutes of active configuration time** (DNS
propagation and reverse-DNS turnaround excluded — those are outside your control).

## Prerequisites

- A VPS with a public IPv4 address (and ideally IPv6). Minimum 2 GB RAM.
  1 GB RAM is technically runnable but leaves no headroom under spam load.
- A domain you control (e.g. `rookery.example`).
- Docker with the Compose v2 plugin. Nothing else on the host is required.
- `git`, `openssl` — available on every Linux distribution.

### Set reverse DNS (PTR record) first

Many providers let you set PTR records in their control panel. Some require a
support ticket. **Do this before anything else** — PTR propagation can take 24–48
hours and is outside your 30-minute budget. Without a correct PTR, your outbound
mail will be rejected by many destinations.

The PTR for your server's IP must resolve back to your primary domain
(e.g. `mail.rookery.example` or just `rookery.example`). Set it now.

## Step 1: Clone the repo

The systemd unit expects the checkout at `/opt/rookery`. Cloning here avoids
editing the unit.

```sh
sudo mkdir -p /opt/rookery
sudo chown "$USER" /opt/rookery
git clone <url> /opt/rookery
cd /opt/rookery
```

## Step 2: Bootstrap

`rookery init` is idempotent and user-local (no `sudo`). It generates:
- `rookery.toml` — instance configuration
- `.env` — random secrets (DB password, master key, session key)
- `Caddyfile` — TLS configuration for Caddy (inert in dev)
- `rookery.service` — staged systemd unit (inert until installed)

```sh
./rookery init --domain rookery.example --email you@example.com --name "My Rookery"
```

Review `rookery.toml` and change anything that doesn't fit your setup. The
defaults are sane; the two values you might want to change are `domain` (already
set by `--domain`) and `contact_email` (used by Let's Encrypt for expiry notices).

## Step 3: Install and start as a systemd service

```sh
sudo ./rookery install
sudo systemctl enable --now rookery
```

`install` copies the staged `./rookery.service` to `/etc/systemd/system/` and
runs `systemctl daemon-reload`. It does not enable or start the unit — `enable
--now` is your deliberate "yes, run this on boot" decision.

The unit runs `rookery start --prod`, which brings up rookery + postgres +
Caddy (TLS on 80/443) + redis + rspamd. Caddy provisions a Let's Encrypt
certificate automatically once DNS is in place.

## Step 4: Make an initial backup

```sh
./rookery backup ~/backups/
```

The archive captures the database, message blobs, config, and `.env` in one
encrypted file. Losing `ROOKERY_MASTER_KEY` bricks the instance's DKIM keys;
the backup preserves it. See the [Backups section in README.md](../../README.md#backups)
for cron automation and the full backup model.

## Step 5: Publish DNS records

On first run, rookery generates DKIM keypairs and logs the DNS records it needs.
Read them with:

```sh
./rookery logs | grep -i dns
```

Or run the DNS checker (which also shows what's propagated vs. what's missing):

```sh
./rookery check-dns
```

Publish these records in your DNS provider. See [dns.md](dns.md) for the full
reference and what each record does. Once they propagate:

- Caddy provisions the Let's Encrypt certificate automatically.
- The web UI becomes available at `https://rookery.example`.
- `./rookery check-dns` goes all-green.

DNS propagation typically takes 5–60 minutes. Use `--resolver 9.9.9.9` to
bypass local caching during the wait:

```sh
./rookery check-dns --resolver 9.9.9.9
```

## Step 6: Create the first user

```sh
./rookery invite create
```

This prints an invite URL to stdout. Visit it in your browser and follow the
signup flow: pick a local-part (your email username), generate a PGP key in the
browser, and export your recovery file from the settings page immediately after.

**The recovery file plus your passphrase is your account.** If you lose either,
your mail is gone — there is no server-side rescue. Store the recovery file
somewhere safe and offline.

You are now both the operator and the first user of your instance.

## Upgrading

```sh
cd /opt/rookery
./rookery update
sudo systemctl restart rookery
```

`update` runs `git pull --ff-only && docker compose build`. It does not restart
automatically — the restart is your deliberate act.

## ClamAV (opt-in, adds ~1 GB RAM)

If you have ≥4 GB RAM and want virus scanning:

```sh
./rookery init --clamav
sudo ./rookery install
sudo systemctl restart rookery
```

`--clamav` regenerates `./rookery.service` with `--profile clamav` in
`ExecStart`, then `install` pushes the updated unit to systemd.

rspamd discovers clamd automatically. Virus-infected messages are rejected at
SMTP time.

## What's not in this guide

- **SMTP submission on 465/587.** Currently only the web UI is the compose
  client. Submission ports are wired up but require a separate credential
  mechanism for SASL (open design question in PLAN.md §11.4).
- **IPv6.** Ensure both IPv4 and IPv6 have correct PTR records if your provider
  gives you a v6 address. Some mail providers prefer v6; a bad v6 PTR will cause
  rejections.
