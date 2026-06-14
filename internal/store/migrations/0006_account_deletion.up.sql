-- purpose distinguishes login vs deletion challenges so each handler only claims
-- its own kind; the existing login INSERT relies on the 'login' default, so no
-- existing query changes.
ALTER TABLE auth_challenges
    ADD COLUMN purpose TEXT NOT NULL DEFAULT 'login'
        CHECK (purpose IN ('login', 'deletion'));
