-- Migration 0003: Phase 2 schema additions.
--
-- New tables:
--   dkim_keys      — per-domain DKIM keypairs (ed25519 + RSA-2048), private keys
--                    AES-256-GCM encrypted at rest with the server master key.
--   outbound_queue — one delivery row per recipient for each sent message.
--   drafts         — unsent compose drafts stored server-side (plaintext JSON).
--
-- Modified tables:
--   messages       — add message_id_header for threading (nullable; old rows NULL).
--
-- Design notes (§8 Phase 2, §11.4, §11.7 of PLAN.md):
--   • DKIM keys are generated at startup if absent (one ed25519 + one RSA-2048
--     per domain). Private keys are encrypted with the server master key;
--     losing the master key requires key regeneration + DNS update.
--   • outbound_queue uses FOR UPDATE SKIP LOCKED for safe concurrent delivery
--     workers; Phase 2 runs a single worker goroutine.
--   • message_id_header enables In-Reply-To threading for both inbound and
--     outbound messages.

-- -------------------------------------------------------------------------
-- dkim_keys
-- -------------------------------------------------------------------------
CREATE TABLE dkim_keys (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id       UUID        NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    selector        TEXT        NOT NULL,
    -- algorithm: "ed25519" or "rsa2048"
    algorithm       TEXT        NOT NULL CHECK (algorithm IN ('ed25519', 'rsa2048')),
    -- DER-encoded raw public key bytes.
    -- ed25519: raw 32-byte public key.
    -- rsa2048: PKCS1 DER-encoded public key.
    public_key_der  BYTEA       NOT NULL,
    -- AES-256-GCM encrypted private key bytes. Nonce (12 bytes) is prepended
    -- to the ciphertext. Encrypted with SHA-256(master_key) as the AES key.
    private_key_enc BYTEA       NOT NULL,
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (domain_id, selector)
);

CREATE INDEX idx_dkim_keys_domain_id ON dkim_keys(domain_id, is_active);

-- -------------------------------------------------------------------------
-- outbound_queue
-- -------------------------------------------------------------------------
CREATE TABLE outbound_queue (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id      UUID        NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    -- envelope recipient (single address per row)
    recipient       TEXT        NOT NULL,
    -- status: pending → delivering → delivered | failed → bounced
    status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'delivering', 'delivered', 'failed', 'bounced')),
    attempts        INT         NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ
);

-- Partial index on rows that need delivery processing.
CREATE INDEX idx_outbound_queue_pending ON outbound_queue(next_retry_at)
    WHERE status IN ('pending', 'delivering');
CREATE INDEX idx_outbound_queue_message_id ON outbound_queue(message_id);

-- -------------------------------------------------------------------------
-- drafts
-- -------------------------------------------------------------------------
CREATE TABLE drafts (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    from_address    TEXT        NOT NULL DEFAULT '',
    to_addresses    TEXT[]      NOT NULL DEFAULT '{}',
    cc_addresses    TEXT[]      NOT NULL DEFAULT '{}',
    bcc_addresses   TEXT[]      NOT NULL DEFAULT '{}',
    subject         TEXT        NOT NULL DEFAULT '',
    body_text       TEXT        NOT NULL DEFAULT '',
    -- in_reply_to is the Message-ID header value of the message being replied to.
    in_reply_to     TEXT,
    -- references_hdr mirrors the References header for the reply chain.
    references_hdr  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_drafts_user_id ON drafts(user_id);

-- -------------------------------------------------------------------------
-- messages — add message_id_header for threading
-- -------------------------------------------------------------------------
-- The Message-ID header value (e.g. "<abc123@domain>") stored for lookup
-- when subsequent replies use In-Reply-To. Nullable; pre-existing rows
-- will have NULL and thread_id will not be set retroactively for them.
ALTER TABLE messages ADD COLUMN message_id_header TEXT;
CREATE INDEX idx_messages_message_id_header ON messages(message_id_header)
    WHERE message_id_header IS NOT NULL;
