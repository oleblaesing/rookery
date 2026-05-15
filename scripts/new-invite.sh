#!/bin/sh
# new-invite.sh — generate a new invite URL for a rookery instance.
#
# Run via the postgres container (which has psql and sh):
#
#   docker compose exec postgres sh /scripts/new-invite.sh [validity_days]
#
# Arguments:
#   validity_days  Optional. Number of days before the invite expires.
#                  If omitted, the invite never expires.
#
# Output:
#   Prints the invite URL to stdout, e.g.:
#     https://rookery.example/invite/a3f2bc8e...
#
# Required environment (provided automatically via compose.yaml / .env):
#   POSTGRES_PASSWORD  — rookery DB password
#
# The domain is always read from rookery.toml (mounted at /rookery/rookery.toml)
# so it stays correct even if the container has not been restarted since a
# domain change.
set -e

VALIDITY_DAYS="${1:-}"

# Reject non-numeric values before they reach the SQL string interpolation
# below. The value is interpolated into the INSERT statement, so this is
# defense-in-depth even though the script is operator-only.
case "$VALIDITY_DAYS" in
    "" )            ;;  # no expiry — fine
    *[!0-9]* )
        echo "new-invite: validity_days must be a positive integer (got '$VALIDITY_DAYS')." >&2
        exit 2
        ;;
esac

# Resolve domain from rookery.toml — the single authoritative source.
# ROOKERY_DOMAIN from the environment is intentionally ignored here: it may be
# stale if the container was not restarted after a domain change in rookery.toml.
if [ ! -f /rookery/rookery.toml ]; then
    echo "new-invite: /rookery/rookery.toml not found." >&2
    echo "  Ensure rookery.toml is bind-mounted into the postgres container." >&2
    exit 1
fi

DOMAIN=$(grep -E '^[[:space:]]*domain[[:space:]]*=' /rookery/rookery.toml \
    | head -1 \
    | sed 's/.*=[[:space:]]*"\([^"]*\)".*/\1/')

if [ -z "$DOMAIN" ]; then
    echo "new-invite: could not parse domain from rookery.toml." >&2
    exit 1
fi

# Generate a 64-char hex token from /dev/urandom.
TOKEN=$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 64 || true)
if [ -z "$TOKEN" ]; then
    echo "new-invite: failed to generate token" >&2
    exit 1
fi

if [ -n "$VALIDITY_DAYS" ]; then
    EXPIRES="now() + interval '${VALIDITY_DAYS} days'"
else
    EXPIRES="NULL"
fi

PGPASSWORD="${POSTGRES_PASSWORD}" psql \
    -h localhost -U rookery -d rookery \
    -q -t -c \
    "INSERT INTO invites (token, expires_at) VALUES ('${TOKEN}', ${EXPIRES});" \
    > /dev/null

# Use http for localhost and bare IP addresses, https everywhere else.
case "$DOMAIN" in
  localhost|127.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*|::1)
    SCHEME="http" ;;
  *)
    SCHEME="https" ;;
esac

printf '%s://%s/invite/%s\n' "$SCHEME" "$DOMAIN" "$TOKEN"
