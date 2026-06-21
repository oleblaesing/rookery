-- Extend the challenge purpose set so key rotation can issue its own challenges
-- without the login/deletion handlers ever claiming them.
ALTER TABLE auth_challenges DROP CONSTRAINT auth_challenges_purpose_check;
ALTER TABLE auth_challenges
    ADD CONSTRAINT auth_challenges_purpose_check
        CHECK (purpose IN ('login', 'deletion', 'rotation'));

-- One row per key change. The old key's detached signature over `statement`
-- (which binds old->new fingerprint) is the attestation; both armored keys are
-- stored so a contact who trusts the chain's starting key can verify every hop
-- offline, even across multiple rotations.
CREATE TABLE key_rotations (
    id                     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    old_fingerprint        TEXT        NOT NULL,
    new_fingerprint        TEXT        NOT NULL,
    old_armored_public_key TEXT        NOT NULL,
    new_armored_public_key TEXT        NOT NULL,
    attestation            TEXT        NOT NULL, -- armored old-key detached signature over `statement`
    statement              TEXT        NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT key_rotations_user_old_new_unique UNIQUE (user_id, old_fingerprint, new_fingerprint)
);

CREATE INDEX idx_key_rotations_old_fingerprint ON key_rotations(old_fingerprint);
CREATE INDEX idx_key_rotations_new_fingerprint ON key_rotations(new_fingerprint);
CREATE INDEX idx_key_rotations_user_id         ON key_rotations(user_id);
