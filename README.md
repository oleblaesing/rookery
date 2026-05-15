# rookery

A PGP-first, self-hostable email server. SMTP + web client in one container.

In *A Song of Ice and Fire*, a rookery is the room where the maester keeps the ravens
that carry sealed messages between holdfasts. Each instance of this project is one
operator's rookery.

---

## What this is

- A mail server (inbound + outbound SMTP) that speaks standard email to the rest of the world.
- A server-rendered web UI where PGP encryption and decryption happen in the browser.
- Self-hostable by one competent Linux user with a domain, in under 30 minutes of active configuration time.
- Invite-only by default; pseudonymous by design; no name, no phone, no recovery email required.

**The server never holds your PGP private key.** It is generated in the browser,
encrypted with your passphrase, and stored only in your browser's IndexedDB and in a
recovery file you download at signup. Losing both means losing your mail — there is no
reset, and the server cannot help you.

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
- Wait. Reputation improves over weeks as your IP establishes a clean sending history.

If reliable delivery to Gmail is a hard requirement from day one, plan to use a
smarthost from the start.

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

# 3. Start the stack. Secrets are generated automatically into .env.
docker compose up -d

# 4. Back up .env — especially ROOKERY_MASTER_KEY.
#    Losing it bricks the instance's DKIM keys, sessions, and ACME credentials.

# 5. Print the DNS records you need to publish.
docker compose exec rookery /opt/rookery/scripts/print-dns.sh

# 6. Publish the DNS records at your registrar and wait for propagation.
#    The server logs DNS check results every few minutes.

# 7. Create the first invite (for yourself).
docker compose exec rookery /opt/rookery/scripts/new-invite.sh

# 8. Visit the printed URL in your browser and complete the signup flow.
```

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
compose.yaml            Dev server, test runner, linter, mailpit — single entry point
rookery.toml.example    Annotated config file schema
Containerfile           The build (multi-stage; also a valid Dockerfile)
PLAN.md                 Full design document
LICENSE                 AGPLv3
```


