-- Migration 0008: relay clients (be a relay rookery).
--
-- relay_clients is the whitelist for the authenticated SMTP submission listener
-- (ports 465/587). Only operators with a row here may submit mail for the relay
-- rookery to forward to the internet on their behalf. See ADR-0030 §3 and Phase B
-- of docs/smarthost-plan.md.
--
-- This is the FIRST server-side stored authentication secret in rookery: end-user
-- auth is PGP challenge/response with nothing stored, but relay clients are remote
-- *operators* speaking a commercial-relay-shaped protocol (SASL username + secret),
-- not end users. secret_hash holds a bcrypt hash; the plaintext secret only ever
-- lives in the downstream operator's [smtp.smarthost] config. A compromised DB
-- alone cannot authenticate as a relay client.

CREATE TABLE relay_clients (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT        NOT NULL UNIQUE,        -- SASL username issued to the downstream
    secret_hash   TEXT        NOT NULL,               -- bcrypt hash of the issued relay secret
    label         TEXT        NOT NULL DEFAULT '',    -- human note: which operator/instance
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    rate_per_hour INT         NOT NULL DEFAULT 200,   -- per-client outbound cap (messages/hour)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);

-- Relayed mail rides the existing outbound_queue so it reuses the same
-- retry/bounce worker. A relayed row has no local messages row: message_id is
-- NULL and the raw (already DKIM-signed-by-the-downstream) blob plus the envelope
-- sender are stored on the queue row itself. relay_client_id tags the row for
-- per-client rate limiting and abuse traceability.
ALTER TABLE outbound_queue
    ALTER COLUMN message_id DROP NOT NULL,
    ADD COLUMN relay_client_id UUID REFERENCES relay_clients(id) ON DELETE SET NULL,
    ADD COLUMN mail_from       TEXT,
    ADD COLUMN blob_sha256     TEXT;

-- Supports the per-client hourly rate-limit count at submission time.
CREATE INDEX idx_outbound_queue_relay_client
    ON outbound_queue(relay_client_id, created_at)
    WHERE relay_client_id IS NOT NULL;
