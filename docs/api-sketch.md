# HTTP Resource Model — Internal Reference

This document sketches the resource model and endpoint shape for the rookery web UI
before any handler is written. It is an internal reference — a shared vocabulary for
implementation — not a public API contract. There is no versioning, no stability
guarantee, and no plan for third-party client support (see ADR-0006).

What is fixed here is the **resource model** — the nouns and their relationships.
Endpoint details, exact field names, and error codes are refined as handlers are written.

---

## Base URL

All routes live under `/api/v1/`.

Example: `GET https://rookery.example/api/v1/messages`

---

## Authentication

One mechanism is accepted on every authenticated endpoint:

- **Session cookie** (`rookery_session`): set on login; HttpOnly, Secure, SameSite=Lax.

Unauthenticated requests to protected endpoints return `401 Unauthorized`.

---

## Error format

All error responses use a stable JSON envelope:

```json
{
  "error": {
    "code": "MESSAGE_NOT_FOUND",
    "message": "No message with that ID exists in this mailbox.",
    "details": {}
  }
}
```

- `code`: string constant identifying the error type — the web UI's JS modules switch
  on this value. Avoid depending on `message` for logic; it may change freely.
- `message`: human-readable description, for display only.
- `details`: optional object with extra context (e.g. which field failed validation).

---

## Pagination

List endpoints use cursor-based pagination (never offset). Response shape:

```json
{
  "items": [...],
  "next_cursor": "<opaque string or null>"
}
```

Pass `?cursor=<value>` on the next request. Default page size: 50. Max: 200 (via
`?limit=`).

---

## Resources

### 1. Auth

Session creation and destruction.

**Endpoints:**

```
GET    /api/v1/auth/challenge  # Issue a one-time nonce for the given address
POST   /api/v1/auth/login      # Verify a signed challenge → session cookie
POST   /api/v1/auth/logout     # Destroy the current session
```

Authentication is PGP challenge/response — the server holds no passphrase and no
passphrase hash.

`GET /api/v1/auth/challenge?address=alice@example.com` returns `{challenge_id, nonce}`.
The nonce is a 32-byte random value (64-char hex). Challenges are single-use and expire
after 5 minutes.

`POST /api/v1/auth/login` accepts `{address, challenge_id, signed_challenge}` where
`signed_challenge` is an ASCII-armored detached PGP signature of the nonce, made by
the user's private key. The server verifies the signature against the stored public key.
On success it returns a session cookie (`rookery_session`, HttpOnly, Secure, SameSite=Lax)
and the authenticated user's profile (same shape as `GET /users/me`). Returns `401` on
invalid or expired challenge, bad signature, or unknown address.

`POST /api/v1/auth/logout` invalidates the session server-side and clears the cookie.
Idempotent — calling it on an already-expired session returns `200`.

---

### 2. Users

A user is an account on the instance. One account, one PGP key, one or many addresses.
The server never holds the PGP private key. See ADR-0010, ADR-0014.

| Field | Type | Description |
|---|---|---|
| `id` | UUID | Stable internal identifier. Not the address; the address can change. |
| `primary_address` | string | The user's primary `local@domain` address. |
| `display_name` | string | Optional display name. May be empty (pseudonymous by default). |
| `public_key_fingerprint` | string | OpenPGP fingerprint of the user's active public key. |
| `created_at` | RFC 3339 | Account creation timestamp. |
| `quota_bytes` | int64 | Mailbox quota. |
| `used_bytes` | int64 | Current mailbox usage. |
| `suspended_at` | RFC 3339 \| null | Non-null if suspended. |
| `totp_enabled` | bool | Whether TOTP 2FA is active for this account. |

**Endpoints:**

```
POST   /api/v1/users/register          # Complete invite registration (upload public key)
GET    /api/v1/users/me                # Get the authenticated user's profile
PATCH  /api/v1/users/me               # Update display_name, etc.
DELETE /api/v1/users/me               # Initiate account deletion (§11.9)
GET    /api/v1/users/me/sessions       # List active sessions (by last-seen timestamp, no IP/UA)
DELETE /api/v1/users/me/sessions/{id}  # Revoke a specific session
```

**`POST /api/v1/users/register` request body:**

```json
{
  "invite_token": "<opaque token from the invite URL>",
  "local_part": "alice",
  "armored_public_key": "<ASCII-armored OpenPGP public key block>"
}
```

This is a single atomic step. The invite token identifies which invite is being
consumed; the local part is validated for availability; the public key is stored.
No intermediate pending-user state is necessary. On success the server returns the
new user's profile and sets a session cookie (the user is logged in immediately
after registration).

No passphrase appears here. Key generation happens entirely in the browser before
this request is made; the keypair is generated without a passphrase. Only the
public key reaches the server. After registration the user is redirected to
settings, where they set a passphrase and export the private key as an encrypted
`.asc` recovery file (OpenPGP.js's built-in s2k per RFC 9580). The server holds no
passphrase and no passphrase hash — authentication after registration is PGP
challenge/response (see `GET /api/v1/auth/challenge` and `POST /api/v1/auth/login`
below).

---

### 3. Keys

The user's public PGP key(s). The server holds public keys only; never private keys.
See ADR-0010, ADR-0011.

| Field | Type | Description |
|---|---|---|
| `fingerprint` | string | Full OpenPGP fingerprint. |
| `armored_public_key` | string | ASCII-armored OpenPGP public key block. |
| `algorithm` | string | e.g. `"cv25519+ed25519"` or `"rsa4096"` (legacy import only). |
| `created_at` | RFC 3339 | When this key was uploaded. |
| `is_active` | bool | Whether this is the current signing/encryption key. |

**Endpoints:**

```
GET    /api/v1/keys/me                  # Get the authenticated user's active public key
PUT    /api/v1/keys/me                  # Upload the user's public key (Phase 1: initial upload
                                        # only; key rotation with attestation lands in Phase 6)
GET    /api/v1/keys/lookup?address=...  # Discover a public key for any address (WKD + cache)
```

The `/keys/lookup` endpoint is the server-side key discovery used by the compose page
(via `partials.js`). It checks: local directory → WKD → optional keyserver. Result
includes the key (if found), discovery method, and a "first seen" timestamp if relevant.

**Note on `PUT /keys/me`:** in Phase 1, the only valid use of this endpoint is the
initial key upload during registration (called by `POST /users/register` internally) or
if the user needs to re-upload a key without changing it. Key *rotation* — replacing one
key with a different one — requires the attestation protocol from ADR-0028 and is a
Phase 6 deliverable. Phase 1 treats a second `PUT` with a different key as an error
(`409 CONFLICT`) so that no key gets silently replaced without the rotation protocol in
place.

---

### 4. Invites

Invite tokens control registration. Created by the operator via
`rookery invite create` (ADR-0033). In Phase 7+ user-issued invites may be
added. See ADR-0008.

| Field | Type | Description |
|---|---|---|
| `token` | string | Opaque random token. URL-safe. |
| `created_at` | RFC 3339 | When the operator created it. |
| `expires_at` | RFC 3339 \| null | Optional expiry. |
| `used_at` | RFC 3339 \| null | When it was consumed; null if still valid. |
| `used_by` | string \| null | Address of the user who consumed it, once used. |

**Endpoints:**

```
GET  /api/v1/invites/{token}   # Validate an invite token (unauthenticated; returns domain info)
```

`GET /api/v1/invites/{token}` returns the instance name, primary domain, and whether the
token is valid and unused. The invite is consumed atomically inside `POST /users/register`
— there is no separate "consume invite" step.

---

### 5. Messages

A message is a stored RFC 5322 email. The server stores the raw blob (encrypted or not
as received) and metadata. Bodies of PGP-encrypted messages are never decrypted
server-side. See §6, §11.5.

| Field | Type | Description |
|---|---|---|
| `id` | UUID | Stable internal ID. |
| `thread_id` | UUID \| null | Thread grouping derived from `In-Reply-To`/`References`. |
| `folder` | string | Virtual folder: `inbox`, `sent`, `drafts`, `trash`, `bounced`. |
| `from_address` | string | Envelope From. |
| `to` | []string | `To` header addresses. |
| `cc` | []string | `Cc` header addresses. May be empty. |
| `subject` | string | Subject header. Leaked in standard SMTP; not encrypted. |
| `date` | RFC 3339 | Message Date header. |
| `size_bytes` | int64 | Size of the raw blob. |
| `is_read` | bool | Read/unread state. |
| `is_starred` | bool | Starred state. |
| `security_state` | string | `pgp_encrypted`, `pgp_signed_plaintext`, `plaintext`. |
| `signature_status` | string | `verified`, `unknown_key`, `invalid`, `none`. |
| `has_attachments` | bool | Whether the message has MIME attachments. |
| `deleted_at` | RFC 3339 \| null | When moved to Trash; null if not deleted. |

**Note on recipients:** `to` and `cc` are the MIME header values — what is visible to
all recipients. BCC recipients are deliberately not exposed in the metadata returned by
the API; they are only present in the raw RFC 5322 blob and only accessible by the
sending user via `GET /messages/{id}/raw`.

**Endpoints:**

```
GET    /api/v1/messages                     # List messages (filterable by folder, thread, etc.)
GET    /api/v1/messages/{id}                # Get message metadata
GET    /api/v1/messages/{id}/raw            # Get the raw RFC 5322 blob (for client-side decrypt)
PATCH  /api/v1/messages/{id}               # Update is_read, is_starred, folder
DELETE /api/v1/messages/{id}               # Soft-delete (move to Trash)
DELETE /api/v1/messages/{id}?permanent=1   # Hard-delete from Trash (irreversible)
POST   /api/v1/messages                     # Submit an outbound message (Phase 2)
POST   /api/v1/messages/drafts              # Save a draft (Phase 2)
GET    /api/v1/messages/drafts/{id}         # Get a draft (raw content for client-side)
PUT    /api/v1/messages/drafts/{id}         # Replace a draft
DELETE /api/v1/messages/drafts/{id}         # Delete a draft
```

**Notes:**

- `GET /api/v1/messages/{id}/raw` returns the raw RFC 5322 message bytes
  (`Content-Type: message/rfc822`). The browser JS module fetches this and decrypts
  locally. The server never decrypts PGP-encrypted bodies.
- `POST /api/v1/messages` and draft endpoints are Phase 2. They are listed here because
  they are part of the stable resource model, but they return `501 Not Implemented` in
  Phase 1.
- The `folder` query parameter on `GET /messages` is the canonical way to get drafts:
  `GET /messages?folder=drafts`. The `/messages/drafts/` sub-path is a convenience
  alias. Both are consistent.
- The `Idempotency-Key` header is accepted on POST endpoints to allow safe retries.

---

### 6. Addresses

A user can hold multiple addresses across multiple domains. See §11.3, ADR-0017.

| Field | Type | Description |
|---|---|---|
| `id` | UUID | Internal ID. |
| `address` | string | Full `local@domain` address. |
| `domain` | string | The domain part. |
| `is_primary` | bool | Whether this is the default From address. |
| `is_alias` | bool | Whether this is an alias (routes to another address). |
| `alias_target` | string \| null | If alias, the target address. |
| `plus_addressing_enabled` | bool | Whether `local+tag@domain` works for this address. |
| `created_at` | RFC 3339 | When the address was associated. |

**Endpoints:**

```
GET    /api/v1/addresses                    # List all addresses for the authenticated user
POST   /api/v1/addresses                    # Add an address (on a verified domain)
DELETE /api/v1/addresses/{id}              # Remove an address
PATCH  /api/v1/addresses/{id}              # Update (set as primary, rename alias, etc.)
POST   /api/v1/addresses/{id}/set-primary  # Set as default From
GET    /api/v1/addresses/{id}/aliases      # List aliases for this address
POST   /api/v1/addresses/{id}/aliases      # Create an alias
DELETE /api/v1/addresses/{id}/aliases/{alias_id}  # Remove an alias
```

---

### 7. Domains

A domain managed by this instance — either the primary domain or a user-verified custom
domain. See §5.2b, §11.3, ADR-0007. Phase 3 is where this resource becomes fully
operational.

| Field | Type | Description |
|---|---|---|
| `id` | UUID | Internal ID. |
| `domain` | string | Fully-qualified domain name. |
| `is_primary` | bool | Whether this is the instance's primary domain. |
| `owner_user_id` | UUID \| null | User who registered it (null for the primary domain). |
| `verified_at` | RFC 3339 \| null | When DNS verification completed; null if pending. |
| `dkim_selector_ed25519` | string | Ed25519 DKIM selector name. |
| `dkim_selector_rsa` | string | RSA-2048 DKIM selector name. |
| `mta_sts_mode` | string | `testing` or `enforce`. |
| `wkd_active` | bool | Whether WKD is serving for this domain. |
| `dns_records` | object | Required DNS records with current verification status. |
| `created_at` | RFC 3339 | When added to the instance. |

`dns_records` is a structured object containing each required record (MX, SPF CNAME,
DKIM selectors, WKD CNAME, MTA-STS CNAME+TXT, TLS-RPT, DMARC, verification challenge)
with `required`, `actual`, and `status` (`ok`, `missing`, `mismatch`) sub-fields.

**Endpoints:**

```
GET    /api/v1/domains                       # List domains for the authenticated user
POST   /api/v1/domains                       # Register a custom domain (starts verification)
GET    /api/v1/domains/{id}                  # Get domain detail including dns_records status
POST   /api/v1/domains/{id}/verify           # Re-check DNS records
DELETE /api/v1/domains/{id}                  # Remove a domain (must have no active addresses)
GET    /api/v1/domains/{id}/dns-records      # Get the full DNS record set (copy-paste format)
```

---

### 8. Known Keys (per-user contact key cache)

The known-keys cache records public keys for correspondent addresses, harvested from
auto-attached keys on inbound messages or discovered via WKD during compose. See §5.3,
§6. This is not an address book — it has no contact fields beyond the key itself.

| Field | Type | Description |
|---|---|---|
| `fingerprint` | string | OpenPGP fingerprint of the cached key. |
| `address` | string | Correspondent address. |
| `armored_public_key` | string | ASCII-armored public key. |
| `first_seen_at` | RFC 3339 | When this key was first associated with this address. |
| `last_seen_at` | RFC 3339 | Most recent inbound message from this address with this key. |
| `source` | string | How discovered: `auto_attach`, `wkd`, `keyserver`, `manual`. |

**Note on identifiers:** known-key entries are identified by `fingerprint`, not by
address. A single address can have multiple keys over time (key rotation). Using
`address` as the sole identifier would make it impossible to represent key history and
would silently overwrite old entries on rotation.

**Endpoints:**

```
GET    /api/v1/known-keys                       # List all cached keys for the authenticated user
GET    /api/v1/known-keys?address=<addr>        # Look up cached key(s) for a specific address
DELETE /api/v1/known-keys/{fingerprint}         # Remove a cached key by fingerprint
PUT    /api/v1/known-keys/{fingerprint}         # Manually set / override a key by fingerprint
```

---

### 9. Export / Import (per-user data portability — ADR-0039)

**Authenticated endpoints:**

```
POST /api/v1/users/me/export
    Queue an async archive export job.
    Returns: { "job_id": "<uuid>", "status": "pending" }
    When ready, sends an inbox notification with download and migration links.

GET  /api/v1/users/me/export/status
    Returns the most recent export job for the authenticated user.
    Returns: { "status": "pending"|"ready"|"downloaded"|"expired"|"failed"|"none",
               "expires_at": "<RFC 3339>" }

GET  /api/v1/users/me/import/fetch?url=<archive-url>
    Proxy endpoint: instance B fetches the encrypted archive from instance A
    and streams it to the browser. HTTPS URLs only; SSRF-protected.
    Returns: application/octet-stream (binary PGP ciphertext)

POST /api/v1/users/me/import
    Accept a plaintext tar stream (already decrypted by the browser).
    Content-Type: application/octet-stream
    Returns: { "imported_messages": N, "imported_blobs": N,
               "imported_known_keys": N, "imported_drafts": N,
               "skipped_messages": N }
```

**Unauthenticated download endpoint:**

```
GET  /export/{token}
    Bearer-token download of a ready export archive. No session required.
    Token is single-use (marked "downloaded" after first serve); file deleted
    after 24-hour expiry. Responds with Content-Disposition attachment and
    Access-Control-Allow-Origin: * (for cross-origin fetch from instance B).
    Returns 404 for missing, expired, or not-yet-ready jobs.
```

---

## Unauthenticated public endpoints

```
GET  /healthz                                    # Health check (no auth required)
GET  /api/v1/status                              # Server version + domain (no auth required)
GET  /invite/{token}                             # Invite landing page (HTML; no auth required)
GET  /export/{token}                      # Export archive download (bearer-token auth)
```

**WKD (Web Key Directory) — Advanced Method only (see ADR-0024):**

```
GET  https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<z-base-32-hash>
GET  https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/policy
```

WKD Advanced Method requests arrive at the `openpgpkey.<domain>` hostname (via CNAME to
the instance), not at the instance's primary hostname. The instance handles these by
inspecting the `Host` header (or the SNI on TLS) and routing accordingly. The Direct
Method (`<domain>/.well-known/openpgpkey/...`) is not supported per ADR-0024.

---

## Phase roadmap for this API

| Phase | What gets added |
|---|---|
| Phase 0 | `/healthz`, `/api/v1/status`. Everything else is stubbed. |
| Phase 1 | Auth (challenge/login/logout), Users (register + me), Keys (upload + lookup), Invites (validate), Messages (receive + read + raw), WKD. |
| Phase 2 | Messages (send + draft), compose-time key discovery, queue status. |
| Phase 3 | Domains (full CRUD + DNS verification), Addresses (multi-address + aliases). |
| Phase 4 | Operator observability endpoints (internal). |
| Phase 5 | Known Keys (full CRUD). Cursor pagination. |
| Phase 4 (now) | Mailbox export/import endpoints (ADR-0039, implemented standalone). |
| Phase 6 | *(export/import already done; remaining: client-side search, chunked attachments)* |
