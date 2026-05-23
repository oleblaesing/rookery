# rookery

A PGP-first, self-hostable email server. SMTP + web client in one container.

In *A Song of Ice and Fire*, a rookery is the room where the maester keeps the ravens
that carry sealed messages between holdfasts. Each instance of this project is one
operator's rookery. Some rookeries — the older, larger ones, whose ravens are trained
to fly to distant lands — also carry messages on behalf of smaller holdfasts whose own
ravens cannot make the journey; in this project, an instance playing that role is
called a *relay rookery* (see [PLAN.md](PLAN.md) §11.10).

---

## What this is

- A mail server (inbound + outbound SMTP) that speaks standard email to the rest of the world.
- A server-rendered web UI where PGP encryption and decryption happen in the browser.
- One binary, one config file, one rebuild command. The traditional self-hosted mail stack — Postfix, Dovecot, Roundcube, rspamd, certbot, a PGP plugin, the WKD/MTA-STS/DKIM glue — collapses into a single Go process. You do not need to learn `main.cf`, Dovecot's config syntax, or `opendkim.conf`, because they are not in the box. Upgrading is `rookery update && sudo systemctl restart rookery` — the Containerfile is the build, so the source tree you pull *is* the upgrade. First-run on a fresh VPS takes under 30 minutes of active configuration time, but that is a side effect of the architecture, not the point of it.
- Invite-only by default; pseudonymous by design; no name, no phone, no recovery email required.

**The server never holds your PGP private key.** It is generated in the browser
during signup. Immediately after registration you are taken to settings where you
set a passphrase and export the recovery file — the only durable copy of your key.
Every login on every device — including the same browser you signed up in — requires
the recovery file alongside your passphrase. Nothing is persisted between sessions.
Losing the recovery file or the passphrase means losing your mail; there is no reset,
and the server cannot help you.

See [PLAN.md](PLAN.md) for the full design document.

---

## Warning: deliverability

**Outbound mail from a fresh IP to Gmail and Outlook will likely land in spam for weeks
or months, regardless of how well-configured your DKIM/SPF/DMARC is.** This is an
IP-reputation problem that affects every new self-hosted mail server. It is not a bug
in rookery; it is a consequence of how large mail providers protect their users from
spam.

What you can do:
- Warm the IP gradually (send small volumes to trusted addresses first).
- Use a transactional email relay (AWS SES, Postmark, Mailgun) as a smarthost — Phase 7
  will make this a first-class configuration option.
- Arrange to send outbound through a **relay rookery** — another rookery instance
  whose IP already has a delivery history, acting as your upstream. Same Phase 7
  configuration, same `[smtp.smarthost]` block, same wire shape (SMTP submission); the
  smarthost just happens to be another rookery rather than a commercial provider.
  rookery signs the user's domain DKIM key *before* handing the message off, so the
  relay rookery is opaque transport — it cannot impersonate users cryptographically,
  only relay what has already been signed. The arrangement is bilateral and configured
  out of band; there is no directory, no federation protocol, no auto-discovery. It is
  one operator agreeing to carry mail for another.
- Wait. Reputation improves over weeks as your IP establishes a clean sending history.

If reliable delivery to Gmail is a hard requirement from day one, plan to use a
smarthost from the start — commercial relay or relay rookery, either fits the same
configuration slot.

> A note on the relay-rookery option: this is genuinely useful, not a magic network
> effect. In early days there will be one or a small handful of relay rookeries; their
> operators will absorb most of the load and most of the abuse exposure (a relay
> rookery's IP gets dirty if its downstream's users send spam, exactly as a commercial
> smarthost's would). Acting as a relay rookery for instances whose operators you do
> not know is unwise. The mechanism creates an option for new operators, not a
> self-balancing network — see PLAN.md §11.10 for the honest framing.

---

## Quick start (operator)

**Prerequisites:** a VPS with a public IPv4 (and ideally IPv6), a domain you control,
and Docker installed (with the Compose v2 plugin). Port 25 must not be blocked by
the VPS provider.

Docker is the only supported runtime; rootless Podman was evaluated and rejected
(privileged-port binding, image-format and short-name quirks). See the header of
`compose.yaml` for the full rationale.

Everything goes through the `rookery` dispatcher script at the repo root.
It wraps `docker compose`, generates secrets and config files, installs the
systemd unit, and exposes every operator action as a subcommand. Run
`./rookery help` for the full list.

```sh
# 1. Clone the repo into /opt/rookery on the VPS.
#    The systemd unit hard-codes this path (WorkingDirectory=/opt/rookery),
#    so cloning elsewhere means editing the unit or running rookery from a
#    non-standard location. Take the standard path.
sudo mkdir -p /opt/rookery
sudo chown "$USER" /opt/rookery
git clone <repo-url> /opt/rookery
cd /opt/rookery

# 2. Bootstrap. User-local: writes .env (random secrets), rookery.toml
#    (from the example, with the flags pre-filled), Caddyfile, and a staged
#    ./rookery.service. No sudo. Idempotent — safe to re-run.
./rookery init \
    --domain rookery.example \
    --email admin@rookery.example \
    --name "My Rookery"
#    Or with no flags to be prompted interactively.

# 3. Back up .env — especially ROOKERY_MASTER_KEY.
#    Losing it bricks the instance's DKIM keys, sessions, and ACME credentials.
#    rookery init prints a one-time reminder.

# 4. Install the systemd unit. Copies ./rookery.service to
#    /etc/systemd/system/ and runs `systemctl daemon-reload`. Run once per
#    host. Does NOT enable or start.
sudo ./rookery install

# 5. Enable and start the service. Standard systemd from here.
sudo systemctl enable --now rookery

# 6. Print the DNS records you need to publish.
#    (The server logs them at startup.)
./rookery logs | grep DNS

# 7. Publish the DNS records at your registrar and wait for propagation.

# 8. Create the first invite (for yourself).
./rookery invite create

# 9. Visit the printed URL in your browser and complete the signup flow.
```

Upgrading later:

```sh
cd /opt/rookery
./rookery update                # git pull --ff-only && docker compose build
sudo systemctl restart rookery
```

---

## Running as a system service

If you ran `./rookery init` and `sudo ./rookery install` per the quickstart,
the systemd unit is already in place and you can `systemctl enable --now
rookery`. The dispatcher generates the unit from a template, fills `User=`
from `--user` (default: `whoami`), and the `install` subcommand handles the
single sudo step (copy to `/etc/systemd/system/`, run `daemon-reload`).

If you skipped the quickstart and want to wire systemd up manually:

```sh
./rookery init           # generates ./rookery.service from your config
sudo ./rookery install   # copies it to /etc/systemd/system/ + daemon-reload
sudo systemctl enable --now rookery
```

The unit's `ExecStart` is `rookery start --prod`, so it brings up Caddy on
80/443, rookery on 8080 behind it, and SMTP on 25.

Logs: `sudo journalctl -u rookery -f` (systemd) or `./rookery logs` (container
stdout).

---

## Local development

Everything runs through the `rookery` dispatcher. No Makefile, no host-side
toolchain required beyond Docker (with the Compose v2 plugin).

```sh
# First run only: bootstrap secrets and rookery.toml.
# Accept the example defaults or pass --domain / --email / --name to skip
# the prompts. Generates ./rookery.service and Caddyfile too — both inert in
# dev, both gitignored.
./rookery init

# Start the dev stack (rookery + postgres + mailpit SMTP sink).
# Web UI at http://localhost:8080. Mailpit UI at http://localhost:8025.
./rookery start
# (./rookery stop / ./rookery restart as needed.)

# Inject a message into the dev stack's inbound SMTP.
./rookery send-mail alice@localhost

# Generate an invite URL.
./rookery invite create

# Run the Go test suite inside a container.
./rookery test

# Run go vet.
./rookery vet

# Drop into a psql shell.
./rookery psql

# Pull upstream changes and rebuild (does not restart).
./rookery update
./rookery restart

# Escape hatches if you need raw docker compose:
./rookery exec rspamd rspamc stat
./rookery compose ps
```

The JS crypto module is bundled inside the container build.

---

## Repository layout

```
cmd/rookery-server/     Main binary: HTTP + SMTP + background workers
internal/
  smtp/                 Inbound + outbound SMTP
  web/                  HTTP handlers, html/template rendering
    templates/          *.gohtml files
  keydir/               Local key directory, WKD publishing, auto-attach
  discovery/            Remote key discovery (WKD, keyservers)
  store/                DB + blob storage
  auth/                 User auth, sessions, 2FA
  queue/                Outbound mail queue
  domains/              Custom-domain registration, DNS verification
  acme/                 Per-domain ACME (Let's Encrypt)
  addresses/            Address routing, aliases, plus-addressing
  lifecycle/            Account deletion, backup, export/import
  config/               Config file + env var loading
web/
  static/               Hand-written CSS, partials.js, vendored crypto assets
  partials/             Source for partials.js (hand-written, no build step)
  crypto/               Source for the JS crypto module (bundled by esbuild)
docs/
  adr/                  Architecture decision records
  api/                  HTTP API documentation
  ops/                  Deployment, DNS, TLS, operator runbook
    rookery.service     systemd unit template
rookery                 Operator + developer dispatcher (single POSIX shell script)
compose.yaml            Service definitions consumed by the dispatcher
Containerfile           The build (multi-stage; also a valid Dockerfile)
PLAN.md                 Full design document
LICENSE                 AGPLv3
```


