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
- One binary, one config file, one rebuild command. The traditional self-hosted mail stack — Postfix, Dovecot, Roundcube, rspamd, certbot, a PGP plugin, the WKD/MTA-STS/DKIM glue — collapses into a single Go process. You do not need to learn `main.cf`, Dovecot's config syntax, or `opendkim.conf`, because they are not in the box. Upgrading is `git pull && docker compose up -d --build` — the Containerfile is the build, so the source tree you pull *is* the upgrade. First-run on a fresh VPS takes under 30 minutes of active configuration time, but that is a side effect of the architecture, not the point of it.
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

```sh
# 1. Clone the repo onto the VPS.
git clone <repo-url> rookery
cd rookery

# 2. Edit the config file.
cp rookery.toml.example rookery.toml
$EDITOR rookery.toml          # Set domain, contact_email, instance_name.

# 3. Build and start the stack. Secrets are generated automatically into .env.
#    --build ensures the image reflects the current source tree (the same
#    command is used to upgrade after `git pull`).
docker compose up -d --build

# 4. Back up .env — especially ROOKERY_MASTER_KEY.
#    Losing it bricks the instance's DKIM keys, sessions, and ACME credentials.

# 5. Print the DNS records you need to publish.
#    (The server also logs these at startup — check: docker compose logs rookery)
docker compose logs rookery | grep DNS

# 6. Publish the DNS records at your registrar and wait for propagation.

# 7. Create the first invite (for yourself).
#    Operator scripts run via the postgres container (which has psql + sh).
#    ROOKERY_DOMAIN is set automatically from rookery.toml by secrets-init.
docker compose exec -T postgres sh /scripts/new-invite.sh

# 8. Visit the printed URL in your browser and complete the signup flow.
```

---

## Running as a system service

To start rookery automatically on boot, install the provided systemd unit:

```sh
# Copy the template, set User= to the unix user that owns /opt/rookery.
sudo cp docs/ops/rookery.service /etc/systemd/system/rookery.service
sudo $EDITOR /etc/systemd/system/rookery.service

sudo systemctl daemon-reload
sudo systemctl enable --now rookery
```

The unit calls `run.sh --profile prod up --build -d`, so it rebuilds the image on
every start. Upgrading is:

```sh
git -C /opt/rookery pull
sudo systemctl restart rookery
```

Logs: `sudo journalctl -u rookery -f` (systemd) or `docker compose logs -f rookery`
(container stdout).

---

## Local development

Everything runs through `compose.yaml`. No Makefile, no host-side toolchain required
beyond Docker (with the Compose v2 plugin).

```sh
# Start the stack (rookery + postgres + mailpit SMTP sink).
# Secrets are generated automatically into .env on first run.
# Mailpit web UI at http://localhost:8025.
docker compose --profile dev up --build

# Run the Go test suite inside a container.
docker compose --profile test run --rm test

# Run go vet.
docker compose --profile lint run --rm lint
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
scripts/                Operator shell scripts (mirrored into container)
web/
  static/               Hand-written CSS, partials.js, vendored crypto assets
  partials/             Source for partials.js (hand-written, no build step)
  crypto/               Source for the JS crypto module (bundled by esbuild)
docs/
  adr/                  Architecture decision records
  api/                  HTTP API documentation
  ops/                  Deployment, DNS, TLS, operator runbook
    rookery.service     systemd unit template
compose.yaml            Dev server, test runner, linter, mailpit — single entry point
rookery.toml.example    Annotated config file schema
Containerfile           The build (multi-stage; also a valid Dockerfile)
PLAN.md                 Full design document
LICENSE                 AGPLv3
```


