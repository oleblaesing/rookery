CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE domains (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    domain      TEXT        NOT NULL UNIQUE,
    is_primary  BOOLEAN     NOT NULL DEFAULT FALSE,
    -- NULL for the primary domain (owned by the instance); for custom domains,
    -- the registering user. FK added below once users exists.
    owner_user_id UUID,
    verified_at TIMESTAMPTZ,
    wkd_active  BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- primary_address is set after the address row is inserted; the circular
    -- dependency (users → addresses → users) is broken with DEFERRABLE constraints.
    primary_address_id    UUID        UNIQUE,
    display_name          TEXT        NOT NULL DEFAULT '',
    login_hash            TEXT        NOT NULL,
    quota_bytes           BIGINT      NOT NULL DEFAULT 5368709120, -- 5 GiB
    used_bytes            BIGINT      NOT NULL DEFAULT 0,
    totp_secret           TEXT,               -- NULL = TOTP not enabled
    suspended_at          TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_keys (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint        TEXT        NOT NULL UNIQUE,
    armored_public_key TEXT        NOT NULL,
    algorithm          TEXT        NOT NULL,
    is_active          BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_user_keys_user_id ON user_keys(user_id);

CREATE TABLE addresses (
    id                     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain_id              UUID        NOT NULL REFERENCES domains(id) ON DELETE RESTRICT,
    local_part             TEXT        NOT NULL, -- lower-cased, no plus-tag
    -- Denormalized (local_part || '@' || domain) for query convenience.
    address                TEXT        NOT NULL UNIQUE,
    is_alias               BOOLEAN     NOT NULL DEFAULT FALSE,
    alias_target_id        UUID        REFERENCES addresses(id) ON DELETE SET NULL,
    plus_addressing_enabled BOOLEAN    NOT NULL DEFAULT TRUE,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT addresses_local_domain_unique UNIQUE (local_part, domain_id)
);

CREATE INDEX idx_addresses_user_id  ON addresses(user_id);
CREATE INDEX idx_addresses_address  ON addresses(address);

-- Add the FK from users back to addresses (deferred above).
ALTER TABLE users
    ADD CONSTRAINT fk_users_primary_address
    FOREIGN KEY (primary_address_id) REFERENCES addresses(id)
    ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED;

-- Add the FK from domains to users (owner) now that users exists.
ALTER TABLE domains
    ADD CONSTRAINT fk_domains_owner
    FOREIGN KEY (owner_user_id) REFERENCES users(id)
    ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED;

-- Enforced at the application layer; this table exists so we can check without
-- hardcoding the strings in queries.
CREATE TABLE reserved_local_parts (
    local_part TEXT PRIMARY KEY
);
INSERT INTO reserved_local_parts VALUES
    ('postmaster'), ('abuse'), ('hostmaster'), ('webmaster');

CREATE TABLE sessions (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT        NOT NULL UNIQUE, -- SHA-256 hex of the raw session token
    -- Stable for the session's lifetime so multiple open tabs don't invalidate
    -- each other's forms.
    csrf_token  TEXT        NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(), -- sliding-expiry: expires_at = last_seen + session_expiry_days
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    -- Deliberately no ip_address or user_agent columns (pseudonymity). Operators
    -- who enable log_connecting_ips get these at runtime, NOT by schema change.
);

CREATE INDEX idx_sessions_user_id    ON sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);

CREATE TABLE invites (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    token       TEXT        NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ,                 -- NULL = no expiry
    used_at     TIMESTAMPTZ,
    used_by_id  UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_invites_token ON invites(token);

CREATE TABLE messages (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    thread_id        UUID,
    folder           TEXT        NOT NULL DEFAULT 'inbox',
    from_address     TEXT        NOT NULL,
    -- MIME header values, NOT envelope recipients. BCC is never stored in
    -- queryable columns — only in the raw blob.
    to_addresses     TEXT[]      NOT NULL DEFAULT '{}',
    cc_addresses     TEXT[]      NOT NULL DEFAULT '{}',
    subject          TEXT        NOT NULL DEFAULT '',
    message_date     TIMESTAMPTZ NOT NULL,
    size_bytes       BIGINT      NOT NULL DEFAULT 0,
    blob_sha256      TEXT        NOT NULL,
    is_read          BOOLEAN     NOT NULL DEFAULT FALSE,
    is_starred       BOOLEAN     NOT NULL DEFAULT FALSE,
    security_state   TEXT        NOT NULL DEFAULT 'plaintext',
    signature_status TEXT        NOT NULL DEFAULT 'none',
    has_attachments  BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Set together with folder = 'trash' (never independently). List queries
    -- filter on folder, not this; the two are kept consistent by the app layer.
    deleted_at       TIMESTAMPTZ,
    received_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_messages_user_id    ON messages(user_id);
CREATE INDEX idx_messages_folder     ON messages(user_id, folder);
CREATE INDEX idx_messages_thread_id  ON messages(thread_id) WHERE thread_id IS NOT NULL;
CREATE INDEX idx_messages_deleted_at ON messages(deleted_at) WHERE deleted_at IS NOT NULL;

-- Keyed by (user_id, fingerprint) — not by address — so key history survives
-- rotation (an address can have multiple entries over time).
CREATE TABLE known_keys (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    address            TEXT        NOT NULL,
    fingerprint        TEXT        NOT NULL,
    armored_public_key TEXT        NOT NULL,
    source             TEXT        NOT NULL DEFAULT 'auto_attach',
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT known_keys_user_fingerprint_unique UNIQUE (user_id, fingerprint)
);

CREATE INDEX idx_known_keys_user_id ON known_keys(user_id);
CREATE INDEX idx_known_keys_address ON known_keys(user_id, address);
