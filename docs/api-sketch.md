# HTTP API Resource Model — Phase 0 Sketch

This document is the Phase 0 artifact required by §8 ("Phase 0 — Foundations") of
PLAN.md. It sketches the resource model and endpoint shape for the rookery HTTP API
before any handler is written. The goal is to have an on-paper contract that grounds
Phase 1 implementation and makes the "deliberately replaceable" principle (ADR-0006)
real from day one.

This is a **sketch**, not a frozen spec. Endpoint details, exact field names, and error
codes will be refined as handlers are written. The sketch is frozen into a versioned,
stable contract during Phase 5 (see ADR-0031). What is fixed now is the **resource
model** — the nouns and their relationships.

---

## Base URL and versioning

All API routes live under `/api/v1/`. Future breaking changes ship under `/api/v2/`.
URL-path versioning was chosen for human readability; see ADR-0031.

Example: `GET https://rookery.example/api/v1/messages`

---

## Authentication

Two mechanisms are accepted on every authenticated endpoint:

- **Session cookie** (`rookery_session`): for browser clients. Set on login; HttpOnly,
  Secure, SameSite=Lax. This is what the web UI uses.
- **Bearer token** (`Authorization: Bearer <token>`): for programmatic clients. Tokens
  are generated in account settings, stored hashed server-side (Argon2id), scoped, and
  revocable. See ADR-0031.

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

- `code`: stable string constant — clients pattern-match on this, never on `message`.
- `message`: human-readable, may change freely within a major version.
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
`?limit=`). See ADR-0031.

---

## Resources

### 1. Users

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
GET    /api/v1/users/me/tokens         # List API tokens
POST   /api/v1/users/me/tokens         # Create an API token
DELETE /api/v1/users/me/tokens/{id}    # Revoke an API token
```

---

### 2. Keys

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
PUT    /api/v1/keys/me                  # Upload / replace the user's public key
GET    /api/v1/keys/lookup?address=...  # Discover a public key for any address (WKD + cache)
```

The `/keys/lookup` endpoint is the server-side key discovery used by the compose page
(via `partials.js`). It checks: local directory → WKD → optional keyserver. Result
includes the key (if found), discovery method, and a "first seen" timestamp if relevant.

---

### 3. Invites

Invite tokens control registration. Created by the operator via `./scripts/new-invite.sh`.
In Phase 7+ user-issued invites may be added. See ADR-0008.

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
POST /api/v1/invites/{token}   # Consume the invite (first step of registration)
```

---

### 4. Messages

A message is a stored RFC 5322 email. The server stores the raw blob (encrypted or not
as received) and metadata. Bodies of PGP-encrypted messages are never decrypted
server-side. See §6, §11.5.

| Field | Type | Description |
|---|---|---|
| `id` | UUID | Stable internal ID. |
| `thread_id` | UUID \| null | Thread grouping derived from `In-Reply-To`/`References`. |
| `folder` | string | Virtual folder: `inbox`, `sent`, `drafts`, `trash`, `bounced`. |
| `from_address` | string | Envelope From. |
| `to_addresses` | []string | Envelope To (may include CC/BCC). |
| `subject` | string | Subject header. Leaked in standard SMTP; not encrypted. |
| `date` | RFC 3339 | Message Date header. |
| `size_bytes` | int64 | Size of the raw blob. |
| `is_read` | bool | Read/unread state. |
| `is_starred` | bool | Starred state. |
| `security_state` | string | `pgp_encrypted`, `pgp_signed_plaintext`, `plaintext`. |
| `signature_status` | string | `verified`, `unknown_key`, `invalid`, `none`. |
| `has_attachments` | bool | Whether the message has MIME attachments. |
| `deleted_at` | RFC 3339 \| null | When moved to Trash; null if not deleted. |

**Endpoints:**

```
GET    /api/v1/messages                     # List messages (filterable by folder, thread, etc.)
GET    /api/v1/messages/{id}                # Get message metadata
GET    /api/v1/messages/{id}/raw            # Get the raw RFC 5322 blob (for client-side decrypt)
PATCH  /api/v1/messages/{id}               # Update is_read, is_starred, folder
DELETE /api/v1/messages/{id}               # Soft-delete (move to Trash)
DELETE /api/v1/messages/{id}?permanent=1   # Hard-delete from Trash (irreversible)
POST   /api/v1/messages                     # Submit an outbound message (PGP/MIME blob POSTed by JS)
POST   /api/v1/messages/drafts              # Save a draft
GET    /api/v1/messages/drafts/{id}         # Get a draft (raw content for client-side)
PUT    /api/v1/messages/drafts/{id}         # Replace a draft
DELETE /api/v1/messages/drafts/{id}         # Delete a draft
```

**Notes:**

- `GET /api/v1/messages/{id}/raw` returns the raw RFC 5322 message bytes
  (`Content-Type: message/rfc822`). The browser JS module fetches this and decrypts
  locally. The server never decrypts PGP-encrypted bodies.
- `POST /api/v1/messages` accepts the fully-encrypted PGP/MIME blob built by the
  browser JS module. The server queues it for outbound SMTP delivery.
- The `Idempotency-Key` header is accepted on POST endpoints. See ADR-0031.

---

### 5. Addresses

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

### 6. Domains

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

### 7. Known Keys (per-user contact key cache)

The known-keys cache records public keys for correspondent addresses, harvested from
auto-attached keys on inbound messages or discovered via WKD during compose. See §5.3,
§6. This is not an address book — it has no contact fields beyond the key itself.

| Field | Type | Description |
|---|---|---|
| `address` | string | Correspondent address. |
| `fingerprint` | string | OpenPGP fingerprint of the cached key. |
| `armored_public_key` | string | ASCII-armored public key. |
| `first_seen_at` | RFC 3339 | When this key was first associated with this address. |
| `last_seen_at` | RFC 3339 | Most recent inbound message from this address with this key. |
| `source` | string | How discovered: `auto_attach`, `wkd`, `keyserver`, `manual`. |

**Endpoints:**

```
GET    /api/v1/known-keys                    # List all cached keys for the authenticated user
GET    /api/v1/known-keys?address=<addr>     # Look up cached key for a specific address
DELETE /api/v1/known-keys/{address}          # Remove a cached key (will re-discover on next compose)
PUT    /api/v1/known-keys/{address}          # Manually set / override a key for an address
```

---

## Unauthenticated public endpoints

```
GET  /healthz                               # Health check (no auth required)
GET  /api/v1/status                         # Server version + domain (no auth required)
GET  /.well-known/openpgpkey/<domain>/...   # WKD endpoint (standard; no auth required)
GET  /invite/{token}                        # Invite landing page (HTML; no auth required)
```

---

## Phase roadmap for this API

| Phase | What gets added |
|---|---|
| Phase 0 | `/healthz`, `/api/v1/status`. Everything else is stubbed. |
| Phase 1 | Users (register + me), Keys (upload + lookup), Invites, Messages (receive + read), WKD. |
| Phase 2 | Messages (send + draft), compose-time key discovery, queue status. |
| Phase 3 | Domains (full CRUD + DNS verification), Addresses (multi-address + aliases). |
| Phase 4 | Operator observability endpoints (internal; not part of the public API surface). |
| Phase 5 | API formally frozen: Bearer tokens, cursor pagination, idempotency keys, semver. Known Keys (full CRUD). |
| Phase 6 | Mailbox export/import endpoints. |
