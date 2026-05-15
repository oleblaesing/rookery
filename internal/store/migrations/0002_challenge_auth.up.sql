-- Migration 0002: replace passphrase-hash auth with PGP challenge/response.
--
-- Changes:
--   • Drop users.login_hash — the server never holds a passphrase hash again.
--   • Add auth_challenges — short-lived nonces issued to login attempts,
--     verified by a detached PGP signature from the user's private key.
--
-- Design (§11.2 / ADR-0015 revision):
--   Authentication is now a two-round trip:
--     1. GET  /api/v1/auth/challenge?address=…
--              → server inserts a row here and returns { challenge_id, nonce }
--     2. POST /api/v1/auth/login
--              → client sends { address, challenge_id, signed_challenge }
--                server verifies the detached PGP signature of the nonce
--                against the stored public key, creates a session on success.
--
--   Challenges expire after 5 minutes and are single-use (used_at IS NOT NULL
--   means already consumed). The application layer enforces both constraints.
--
--   After this migration the server holds no authentication material at all:
--     - No passphrase, no passphrase hash, no encrypted private key.
--     - The only auth-relevant data is the public key (already in user_keys
--       and published via WKD anyway).
--   A full breach of the database leaks zero authentication material.

ALTER TABLE users DROP COLUMN login_hash;

CREATE TABLE auth_challenges (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- address is the full email address the challenge was issued for.
    -- We resolve it to a user_id at claim time (not issue time) so that
    -- a challenge for a nonexistent address is indistinguishable from one
    -- for an existing address (timing resistance).
    address     TEXT        NOT NULL,
    -- nonce is a 32-byte random value encoded as lowercase hex (64 chars).
    -- The client signs exactly this string with their PGP key.
    nonce       TEXT        NOT NULL,
    -- used_at is set when the challenge is successfully claimed. Single-use.
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Challenges are looked up by id; a partial index on unexpired+unclaimed rows
-- keeps the lookup fast even if old rows accumulate before the purge worker runs.
CREATE INDEX idx_auth_challenges_id_active
    ON auth_challenges(id)
    WHERE used_at IS NULL;
