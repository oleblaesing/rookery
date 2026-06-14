-- The whitelist for the authenticated submission listener (465/587). This is the
-- only server-side stored auth secret in rookery: secret_hash is a bcrypt hash;
-- the plaintext secret only lives in the downstream operator's config, so a
-- compromised DB alone cannot authenticate as a relay client.
CREATE TABLE relay_clients (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT        NOT NULL UNIQUE,
    secret_hash   TEXT        NOT NULL,
    label         TEXT        NOT NULL DEFAULT '',
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    rate_per_hour INT         NOT NULL DEFAULT 200,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);

-- A relayed row has no local messages row: message_id is NULL and the
-- already-signed blob plus envelope sender live on the queue row itself.
-- relay_client_id tags the row for per-client rate limiting and traceability.
ALTER TABLE outbound_queue
    ALTER COLUMN message_id DROP NOT NULL,
    ADD COLUMN relay_client_id UUID REFERENCES relay_clients(id) ON DELETE SET NULL,
    ADD COLUMN mail_from       TEXT,
    ADD COLUMN blob_sha256     TEXT;

-- Supports the per-client hourly rate-limit count at submission time.
CREATE INDEX idx_outbound_queue_relay_client
    ON outbound_queue(relay_client_id, created_at)
    WHERE relay_client_id IS NOT NULL;
