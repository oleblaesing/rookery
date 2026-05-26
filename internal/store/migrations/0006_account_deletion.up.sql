-- Migration 0006: extend auth_challenges for deletion flow.
--
-- A single auth_challenges table handles both login and account-deletion
-- challenges. The purpose column ('login' | 'deletion') distinguishes the two
-- at the query level so each handler only claims its own kind. The existing
-- INSERT for login challenges does not specify purpose and gets the default
-- 'login'; no existing query needs changing.
--
-- Design choice (vs. a separate deletion_challenges table): the shape is
-- identical — nonce, TTL, single-use — and adding a discriminator column is
-- lower schema surface than a new table.

ALTER TABLE auth_challenges
    ADD COLUMN purpose TEXT NOT NULL DEFAULT 'login'
        CHECK (purpose IN ('login', 'deletion'));
