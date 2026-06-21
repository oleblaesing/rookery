DROP TABLE IF EXISTS key_rotations;

ALTER TABLE auth_challenges DROP CONSTRAINT auth_challenges_purpose_check;
ALTER TABLE auth_challenges
    ADD CONSTRAINT auth_challenges_purpose_check
        CHECK (purpose IN ('login', 'deletion'));
