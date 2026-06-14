CREATE TABLE dkim_keys (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id       UUID        NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    selector        TEXT        NOT NULL,
    algorithm       TEXT        NOT NULL CHECK (algorithm IN ('ed25519', 'rsa2048')),
    -- ed25519: raw 32-byte public key. rsa2048: PKCS1 DER.
    public_key_der  BYTEA       NOT NULL,
    -- Nonce (12 bytes) prepended to the AES-256-GCM ciphertext; the AES key is
    -- SHA-256(master_key).
    private_key_enc BYTEA       NOT NULL,
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (domain_id, selector)
);

CREATE INDEX idx_dkim_keys_domain_id ON dkim_keys(domain_id, is_active);

CREATE TABLE outbound_queue (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id      UUID        NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    recipient       TEXT        NOT NULL,
    -- status flow: pending → delivering → delivered | failed → bounced
    status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'delivering', 'delivered', 'failed', 'bounced')),
    attempts        INT         NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ
);

-- Partial index on rows that still need delivery processing.
CREATE INDEX idx_outbound_queue_pending ON outbound_queue(next_retry_at)
    WHERE status IN ('pending', 'delivering');
CREATE INDEX idx_outbound_queue_message_id ON outbound_queue(message_id);

CREATE TABLE drafts (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    from_address    TEXT        NOT NULL DEFAULT '',
    to_addresses    TEXT[]      NOT NULL DEFAULT '{}',
    cc_addresses    TEXT[]      NOT NULL DEFAULT '{}',
    bcc_addresses   TEXT[]      NOT NULL DEFAULT '{}',
    subject         TEXT        NOT NULL DEFAULT '',
    body_text       TEXT        NOT NULL DEFAULT '',
    in_reply_to     TEXT,
    references_hdr  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_drafts_user_id ON drafts(user_id);

-- Nullable: pre-existing rows stay NULL and aren't threaded retroactively.
ALTER TABLE messages ADD COLUMN message_id_header TEXT;
CREATE INDEX idx_messages_message_id_header ON messages(message_id_header)
    WHERE message_id_header IS NOT NULL;
