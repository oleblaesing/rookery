#!/bin/sh
# run.sh — wrapper around `docker compose` that ensures .env and rookery.toml
# exist before Compose starts any containers.
#
# Docker Compose snapshots env_file into each container at *creation* time,
# which happens before any service runs. Secrets must therefore exist on disk
# before `docker compose up` is called. This script handles that on the host.
#
# Usage (drop-in replacement for `docker compose`):
#   ./run.sh up --build
#   ./run.sh --profile dev up --build
#   ./run.sh down -v
#   ./run.sh logs -f
#
# After the first run, .env already exists and this script is a fast no-op
# before exec-ing into docker compose.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV="$SCRIPT_DIR/.env"

# ---------------------------------------------------------------------------
# rookery.toml check — operator must create this before the stack can start
# ---------------------------------------------------------------------------
if [ ! -f "$SCRIPT_DIR/rookery.toml" ]; then
  echo "" >&2
  echo "run.sh: rookery.toml is missing." >&2
  echo "" >&2
  echo "  Copy the example and edit it before starting the stack:" >&2
  echo "    cp rookery.toml.example rookery.toml" >&2
  echo "    \$EDITOR rookery.toml      # set domain, contact_email, ..." >&2
  echo "" >&2
  echo "  Then re-run: ./run.sh --profile dev up --build" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Secret generation — idempotent, only writes variables that are absent/empty
# ---------------------------------------------------------------------------
if ! command -v openssl >/dev/null 2>&1; then
  echo "run.sh: openssl is required to generate secrets. Install it and retry." >&2
  exit 1
fi

touch "$ENV"

gen() {
  local var="$1" val="${2:-}" cur
  cur=$(grep -E "^${var}=" "$ENV" 2>/dev/null | cut -d= -f2-)
  if [ -z "$cur" ]; then
    grep -v "^${var}=" "$ENV" > "${ENV}.tmp" 2>/dev/null && mv "${ENV}.tmp" "$ENV" || true
    [ -z "$val" ] && val=$(openssl rand -hex 32)
    printf '%s=%s\n' "$var" "$val" >> "$ENV"
    echo "run.sh: generated $var"
  fi
}

# DB password is written under both names:
#   ROOKERY_DB_PASSWORD — read by the Go server
#   POSTGRES_PASSWORD   — read by the postgres container image
DB_PASS=$(grep -E "^ROOKERY_DB_PASSWORD=" "$ENV" 2>/dev/null | cut -d= -f2-)
[ -z "$DB_PASS" ] && DB_PASS=$(openssl rand -hex 32)
gen ROOKERY_DB_PASSWORD "$DB_PASS"
gen POSTGRES_PASSWORD   "$DB_PASS"

gen ROOKERY_MASTER_KEY
gen ROOKERY_SESSION_KEY

# ---------------------------------------------------------------------------
# Caddyfile generation — only when --profile prod is requested
# ---------------------------------------------------------------------------
USES_PROD=false
prev=""
for arg in "$@"; do
  if [ "$arg" = "prod" ] && [ "$prev" = "--profile" ]; then
    USES_PROD=true
  fi
  prev="$arg"
done

if $USES_PROD && [ ! -f "$SCRIPT_DIR/Caddyfile" ]; then
  DOMAIN=$(grep -E '^\s*domain\s*=' "$SCRIPT_DIR/rookery.toml" \
    | head -1 | sed 's/.*=\s*"\([^"]*\)".*/\1/')

  if [ -z "$DOMAIN" ]; then
    echo "run.sh: could not read domain from rookery.toml — set it before using --profile prod." >&2
    exit 1
  fi
  if [ "$DOMAIN" = "rookery.example" ]; then
    echo "run.sh: domain is still 'rookery.example' in rookery.toml — change it to your real domain first." >&2
    exit 1
  fi

  # contact_email is optional; include it in Caddy's global block if set.
  EMAIL=$(grep -E '^\s*contact_email\s*=' "$SCRIPT_DIR/rookery.toml" \
    | head -1 | sed 's/.*=\s*"\([^"]*\)".*/\1/' || true)

  {
    if [ -n "$EMAIL" ] && [ "$EMAIL" != "admin@rookery.example" ]; then
      printf '{\n\temail %s\n}\n\n' "$EMAIL"
    fi
    # Primary domain — web UI, API, and WKD key discovery endpoint.
    printf '%s {\n\treverse_proxy rookery:8080\n}\n\nopenpgpkey.%s {\n\treverse_proxy rookery:8080\n}\n' \
      "$DOMAIN" "$DOMAIN"
  } > "$SCRIPT_DIR/Caddyfile"

  echo "run.sh: generated Caddyfile for domain '$DOMAIN'"
fi

# ---------------------------------------------------------------------------
# Hand off to docker compose, forwarding all arguments unchanged
# ---------------------------------------------------------------------------
exec docker compose "$@"
