#!/bin/sh
# send-test-mail.sh — inject a test message into rookery's inbound SMTP.
#
# Sends directly to rookery port 25 via curl's SMTP support.
# No extra tools required beyond curl for plaintext messages.
# Encrypted messages additionally require gpg.
#
# Usage:
#   ./scripts/send-test-mail.sh [--encrypted --pubkey <key.asc>] <to> [from] [subject] [body]
#   ./scripts/send-test-mail.sh [--encrypted --fetch-key]         <to> [from] [subject] [body]
#
# Flags (must come before positional arguments):
#   --encrypted      Send a PGP/MIME encrypted message instead of plaintext.
#                    Requires one of the key source flags below.
#   --pubkey <file>  Path to an ASCII-armored OpenPGP public key file for the
#                    recipient. Used as the encryption key.
#   --fetch-key      Fetch the recipient's public key from the local rookery
#                    instance via WKD (/.well-known/openpgpkey/...).
#                    Requires ROOKERY_HTTP to point at the running instance
#                    (default: http://localhost:8080).
#
# Examples:
#   # Plaintext (original behaviour)
#   ./scripts/send-test-mail.sh alice@localhost
#   ./scripts/send-test-mail.sh alice@localhost bob@example.com "hi" "hello!"
#
#   # Encrypted — supply the recipient's exported public key directly
#   ./scripts/send-test-mail.sh --encrypted --pubkey /tmp/alice.asc alice@localhost
#
#   # Encrypted — auto-fetch the key from the running rookery instance via WKD
#   ./scripts/send-test-mail.sh --encrypted --fetch-key alice@localhost
#
# Environment variables:
#   ROOKERY_SMTP   SMTP endpoint  (default: smtp://localhost:25)
#   ROOKERY_HTTP   HTTP base URL  (default: http://localhost:8080)
#                  Used only with --fetch-key.
#
# Requires: curl, running dev stack (docker compose --profile dev up)
# Encrypted mode additionally requires: gpg (gnupg2)
set -e

# --------------------------------------------------------------------------
# Parse flags
# --------------------------------------------------------------------------
ENCRYPTED=0
PUBKEY_FILE=""
FETCH_KEY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --encrypted)
            ENCRYPTED=1
            shift
            ;;
        --pubkey)
            shift
            PUBKEY_FILE="${1:-}"
            if [ -z "$PUBKEY_FILE" ]; then
                echo "error: --pubkey requires a file path argument" >&2
                exit 1
            fi
            shift
            ;;
        --fetch-key)
            FETCH_KEY=1
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "error: unknown flag: $1" >&2
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

# --------------------------------------------------------------------------
# Positional arguments
# --------------------------------------------------------------------------
TO="${1:-}"
FROM="${2:-sender@example.com}"
SUBJECT="${3:-test message $(date '+%H:%M:%S')}"
BODY="${4:-This is a test message sent via send-test-mail.sh at $(date).}"
ROOKERY_SMTP="${ROOKERY_SMTP:-smtp://localhost:25}"
ROOKERY_HTTP="${ROOKERY_HTTP:-http://localhost:8080}"

if [ -z "$TO" ]; then
    echo "Usage: $0 [--encrypted --pubkey <file> | --fetch-key] <to> [from] [subject] [body]" >&2
    echo "  e.g. $0 alice@localhost" >&2
    echo "  e.g. $0 --encrypted --fetch-key alice@localhost" >&2
    exit 1
fi

# --------------------------------------------------------------------------
# Validate encrypted-mode flag combinations
# --------------------------------------------------------------------------
if [ "$ENCRYPTED" -eq 1 ] && [ -z "$PUBKEY_FILE" ] && [ "$FETCH_KEY" -eq 0 ]; then
    echo "error: --encrypted requires either --pubkey <file> or --fetch-key" >&2
    exit 1
fi

if [ -n "$PUBKEY_FILE" ] && [ "$FETCH_KEY" -eq 1 ]; then
    echo "error: --pubkey and --fetch-key are mutually exclusive" >&2
    exit 1
fi

if { [ -n "$PUBKEY_FILE" ] || [ "$FETCH_KEY" -eq 1 ]; } && [ "$ENCRYPTED" -eq 0 ]; then
    echo "error: --pubkey / --fetch-key require --encrypted" >&2
    exit 1
fi

# --------------------------------------------------------------------------
# Helper: send a raw RFC 5322 message via SMTP
# --------------------------------------------------------------------------
smtp_send() {
    printf '%s' "$1" | curl -s \
        --url "${ROOKERY_SMTP}" \
        --mail-from "${FROM}" \
        --mail-rcpt "${TO}" \
        --upload-file -
}

# --------------------------------------------------------------------------
# Plaintext path
# --------------------------------------------------------------------------
if [ "$ENCRYPTED" -eq 0 ]; then
    MESSAGE="From: ${FROM}
To: ${TO}
Subject: ${SUBJECT}
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

${BODY}
"
    smtp_send "$MESSAGE"
    echo "sent (plaintext): ${SUBJECT}"
    echo "  from: ${FROM}"
    echo "  to:   ${TO}"
    exit 0
fi

# --------------------------------------------------------------------------
# Encrypted path — requires gpg
# --------------------------------------------------------------------------
if ! command -v gpg > /dev/null 2>&1; then
    echo "error: gpg is required for encrypted messages but was not found in PATH" >&2
    echo "  Install gnupg2 (e.g. 'apt install gnupg2' or 'brew install gnupg')" >&2
    exit 1
fi

# Use an isolated temporary GPG homedir so we never touch the user's keyring.
GPG_HOME="$(mktemp -d)"
trap 'rm -rf "$GPG_HOME"' EXIT INT TERM
GPG="gpg --homedir $GPG_HOME --batch --yes --quiet"

# --------------------------------------------------------------------------
# Obtain the recipient's public key
# --------------------------------------------------------------------------
if [ "$FETCH_KEY" -eq 1 ]; then
    # Derive WKD Advanced Method URL.
    # hash = z-base-32( SHA-1( lowercase(local-part) ) )
    # We rely on gpg's built-in WKD fetch (--locate-external-key) with a
    # custom keyserver URL, which is the most portable approach.  Alternatively
    # we call the WKD endpoint with curl and import the binary key bytes.

    LOCAL_PART="${TO%%@*}"
    DOMAIN_PART="${TO##*@}"

    # Compute the WKD hash via gpg's internal facility: generate a dummy key
    # and ask gpg to locate the recipient externally.  A simpler approach that
    # avoids needing gpg for hashing is to use the ROOKERY_HTTP API.
    # We prefer curl + the binary WKD endpoint since gpg WKD fetching needs
    # the key on a reachable HTTPS host, which is not available in local dev.

    # Compute z-base-32(SHA-1(lower(local-part))) using Python if available,
    # otherwise fall back to a pure-shell implementation.
    if command -v python3 > /dev/null 2>&1; then
        WKD_HASH=$(python3 - "$LOCAL_PART" <<'PYEOF'
import sys, hashlib, base64
# z-base-32 alphabet (RFC 6189 / WKD spec)
ALPHA = "ybndrfg8ejkmcpqxot1uwisza345h769"
local = sys.argv[1].lower().encode()
digest = hashlib.sha1(local).digest()
# Encode 20 bytes → 32 z-base-32 characters
bits = int.from_bytes(digest, 'big')
chars = []
for _ in range(32):
    chars.append(ALPHA[bits & 0x1f])
    bits >>= 5
print(''.join(reversed(chars)))
PYEOF
)
    else
        echo "error: python3 is required for --fetch-key to compute the WKD hash" >&2
        exit 1
    fi

    WKD_URL="${ROOKERY_HTTP}/.well-known/openpgpkey/${DOMAIN_PART}/hu/${WKD_HASH}"
    PUBKEY_FILE="${GPG_HOME}/recipient.pgp"

    echo "fetching public key via WKD: ${WKD_URL}" >&2
    HTTP_STATUS=$(curl -s -o "$PUBKEY_FILE" -w "%{http_code}" "${WKD_URL}")
    if [ "$HTTP_STATUS" != "200" ]; then
        echo "error: WKD key fetch returned HTTP ${HTTP_STATUS}" >&2
        echo "  URL: ${WKD_URL}" >&2
        echo "  Make sure the recipient has registered a key and the dev stack is running." >&2
        exit 1
    fi

    # The WKD endpoint returns binary (non-armored) key bytes — import directly.
    $GPG --import "$PUBKEY_FILE" 2>/dev/null
    KEY_IMPORTED=1
fi

# Import armored key file (only when --pubkey was used; --fetch-key already imported above)
if [ -z "${KEY_IMPORTED:-}" ] && [ -n "$PUBKEY_FILE" ]; then
    if [ ! -f "$PUBKEY_FILE" ]; then
        echo "error: public key file not found: ${PUBKEY_FILE}" >&2
        exit 1
    fi
    $GPG --import "$PUBKEY_FILE" 2>/dev/null
fi

# Trust the imported key ultimately so gpg does not refuse to encrypt to it.
FINGERPRINT=$($GPG --with-colons --list-keys 2>/dev/null \
    | awk -F: '/^fpr/{print $10; exit}')

if [ -z "$FINGERPRINT" ]; then
    echo "error: could not read fingerprint from the imported key" >&2
    exit 1
fi

echo "${FINGERPRINT}:6:" | $GPG --import-ownertrust 2>/dev/null

# --------------------------------------------------------------------------
# Encrypt the body
# --------------------------------------------------------------------------
BODY_FILE="${GPG_HOME}/body.txt"
CIPHER_FILE="${GPG_HOME}/body.pgp"

printf '%s\n' "$BODY" > "$BODY_FILE"

$GPG --armor \
    --recipient "$FINGERPRINT" \
    --output "$CIPHER_FILE" \
    --encrypt "$BODY_FILE" 2>/dev/null

ENCRYPTED_BODY=$(cat "$CIPHER_FILE")

# --------------------------------------------------------------------------
# Build RFC 3156 PGP/MIME multipart/encrypted message
# --------------------------------------------------------------------------
# RFC 3156 §4 requires a two-part multipart/encrypted structure:
#   Part 1: application/pgp-encrypted  (version declaration)
#   Part 2: application/octet-stream   (the PGP message block)
# The browser's extractPGPBlock() searches for "-----BEGIN PGP MESSAGE-----"
# anywhere in the raw message bytes, so Part 2 just needs to contain it.

BOUNDARY="rookery_pgp_$(date '+%s')_boundary"
DATE_HDR="$(date -R 2>/dev/null || date '+%a, %d %b %Y %H:%M:%S %z')"
MESSAGE_ID="test-$(date '+%s')@rookery.test"

MESSAGE="From: ${FROM}
To: ${TO}
Subject: ${SUBJECT}
Date: ${DATE_HDR}
Message-ID: <${MESSAGE_ID}>
MIME-Version: 1.0
Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"${BOUNDARY}\"

--${BOUNDARY}
Content-Type: application/pgp-encrypted

Version: 1

--${BOUNDARY}
Content-Type: application/octet-stream; name=\"encrypted.asc\"
Content-Disposition: inline; filename=\"encrypted.asc\"

${ENCRYPTED_BODY}

--${BOUNDARY}--
"

smtp_send "$MESSAGE"
echo "sent (pgp-encrypted): ${SUBJECT}"
echo "  from: ${FROM}"
echo "  to:   ${TO}"
echo "  key:  ${FINGERPRINT}"
