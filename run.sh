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
# Hand off to docker compose, forwarding all arguments unchanged
# ---------------------------------------------------------------------------
exec docker compose "$@"
