-- Reverse migration 0002: restore passphrase-hash auth.
DROP TABLE IF EXISTS auth_challenges;

ALTER TABLE users ADD COLUMN login_hash TEXT NOT NULL DEFAULT '';
