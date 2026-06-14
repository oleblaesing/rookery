ALTER TABLE users DROP COLUMN login_hash;

CREATE TABLE auth_challenges (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Resolved to a user_id at claim time (not issue time) so a challenge for a
    -- nonexistent address is indistinguishable from one for an existing address
    -- (timing resistance).
    address     TEXT        NOT NULL,
    -- The client signs exactly this string with their PGP key.
    nonce       TEXT        NOT NULL,
    used_at     TIMESTAMPTZ, -- set when claimed; single-use
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Partial index on unexpired+unclaimed rows keeps the lookup fast even if old
-- rows accumulate before the purge worker runs.
CREATE INDEX idx_auth_challenges_id_active
    ON auth_challenges(id)
    WHERE used_at IS NULL;
