# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`rookery` is a PGP-first, self-hostable mail server — inbound/outbound SMTP, WKD key publishing, and a server-rendered web client — in a single Go binary and one container. The server never holds users' PGP private keys. Authentication is challenge/response signed by the private key; no passphrase hash is stored server-side. See `PLAN.md` for the full design document and `docs/adr/` for architectural decision records.

Current phase: **Phase 4** (custom domains). Phases 1–3 are complete. Phase 3 delivered HTTPS via Caddy sidecar (`--profile prod`); see `docs/adr/ADR-0024.md`.

## Development commands

The `rookery` shell-script dispatcher at the repo root is the single entry point for everything — operator ops, dev workflows, tests, lint. It wraps `docker compose`, generates `.env` (random secrets), `rookery.toml`, `Caddyfile`, and a staged `./rookery.service` on first use, and exposes every action as a subcommand. See `docs/adr/ADR-0033.md` for the rationale and the full subcommand surface. Always use it instead of `docker compose` directly; escape hatches (`./rookery exec <svc> <cmd>` and `./rookery compose <args>`) cover ad-hoc cases.

```sh
# First run only: bootstrap. User-local, no sudo. Generates the full set of
# config files; --domain / --email / --name skip the prompts.
./rookery init
./rookery init --domain rookery.example --email admin@rookery.example --name "My Rookery"

# Start dev stack (rookery + postgres + mailpit at http://localhost:8025).
# Web UI at http://localhost:8080. Defaults to dev — --prod enables Caddy on 80/443.
./rookery start
./rookery start --prod

# Stop / restart
./rookery stop
./rookery restart

# Upgrade in place (does not restart)
./rookery update

# Production: install the systemd unit (one sudo step) and let systemd run it
sudo ./rookery install
sudo systemctl enable --now rookery

# Run the Go test suite, go vet
./rookery test
./rookery vet

# Generate an invite URL
./rookery invite create

# Inject a message into the dev stack (plaintext or encrypted)
./rookery send-mail alice@localhost
./rookery send-mail --encrypted --fetch-key alice@localhost

# Drop into a psql shell
./rookery psql

# Tail logs (default: rookery)
./rookery logs [service]
```

**Iterating on Go code** without rebuilding the container: `go run ./cmd/rookery serve` works for the HTTP server if `ROOKERY_CONFIG`, `ROOKERY_DB_URL`, etc. are in the environment. The JS crypto module requires the container build (esbuild runs only inside the Containerfile).

## Architecture

### Process structure

One binary (`cmd/rookery/main.go`) starts:
- HTTP server on port 8080 (chi router, `net/http`). In production, Caddy proxies HTTPS→HTTP to this port; in dev, hit it directly.
- SMTP inbound listener on port 25 (`emersion/go-smtp`)

Both share a single `*store.Store` (Postgres pool + blob root path). Graceful shutdown on SIGINT/SIGTERM with a 30-second timeout.

### Storage

- **Postgres** (`jackc/pgx/v5`): all metadata, sessions, keys, messages metadata, invites.
- **Content-addressed blob store**: raw `.eml` files at `<message_dir>/sha256/<ab>/<cd>/<hash>.eml`. Blobs are written atomically (temp file + rename). Multiple recipients share one blob.
- **Migrations**: SQL files in `internal/store/migrations/`, embedded via `embed.FS`, applied at startup by `golang-migrate`. Migration files are `NNNN_name.up.sql` / `NNNN_name.down.sql`.

### HTTP layer (`internal/web/`)

- Routes registered in `routes.go`. HTML pages use `auth.Middleware(ss, unauthHTML)`; API endpoints use `auth.Middleware(ss, unauthAPI)`.
- Templates in `internal/web/templates/` as `.gohtml` files, rendered via Go `html/template`.
- Static files served from `web/static/` (dev) or `/opt/rookery/web/static` (container).
- **CSRF**: synchronizer-token pattern. The `rookery_csrf` cookie is not HttpOnly (JS reads it). Mutating requests send the token in `X-CSRF-Token` header (API/partials.js) or `_csrf` form field (plain HTML forms). `auth.CSRFMiddleware` handles verification.

### Auth model (`internal/auth/`)

- **No passphrase hash stored server-side.** Login is PGP challenge/response: server issues a nonce, browser signs it with the user's private key, server verifies against the stored public key.
- Sessions stored in Postgres as `SHA-256(raw_token)`. The raw token goes in an HttpOnly `rookery_session` cookie. Sliding expiry (`session_expiry_days` from config, default 7 days).
- `SessionFromContext` / `UserIDFromContext` retrieve session data injected by `auth.Middleware`.

### SMTP (`internal/smtp/`)

- `inboundBackend` / `inboundSession` implement the `go-smtp` backend interface.
- Plus-addressing: `alice+tag@domain` resolves to `alice@domain` in `resolveRecipient`.
- Message metadata (subject, date, to/cc, PGP security state, attachments) extracted via `go-message`; raw blob written once; a `messages` row inserted per recipient.
- AUTH not offered on port 25 (inbound MX only; submission is Phase 2).

### Browser JS

- **`web/static/crypto.js`**: bundled from `web/crypto/index.js` by esbuild inside the Containerfile. Uses `openpgp` (OpenPGP.js 6.1.1, pinned). Exposed as the `RookeryCrypto` global. Loaded only on compose/read pages.
- **`web/static/partials.js`**: hand-written, no framework, no build step. Provides `fetch + swap` helpers for partial-page updates (recipient key hints, mark-as-read, etc.). Endpoints called by it return **HTML fragments**, not JSON. JSON is reserved for the crypto module's raw-data needs.
- **`web/static/style.css`**: hand-written, single file. No CSS framework.

### Key design constraints to preserve

- The server **must never receive the user's PGP private key** in any form.
- No third-party scripts in the browser (OpenPGP.js is the single accepted dependency, SRI-pinned).
- No SPA framework. Server-rendered HTML + minimal hand-written JS only.
- No HTMX or equivalent library — `partials.js` covers the same surface in ~200 lines.
- No CSS framework (not even classless ones).
- Every new Go dependency needs justification; prefer stdlib. See PLAN.md §2 principle 12.

### Config and secrets (all generated by `rookery init`, all gitignored)

- `rookery.toml` (generated by `./rookery init`): domain, HTTP, SMTP, storage, policy settings.
- `Caddyfile`: Caddy reverse-proxy config for TLS/HTTPS in prod. Inert in dev.
- `.env`: `ROOKERY_DB_PASSWORD`, `POSTGRES_PASSWORD`, `ROOKERY_MASTER_KEY`, `ROOKERY_SESSION_KEY`. Back up `ROOKERY_MASTER_KEY` — losing it bricks DKIM keys.
- `rookery.service`: staged systemd unit with `User=` filled in. Promoted to `/etc/systemd/system/` by `sudo rookery install`.
- Config loaded in `internal/config/config.go`. The `ROOKERY_CONFIG` env var overrides the default path `/etc/rookery/rookery.toml`.
