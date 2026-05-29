-- Migration 0007: per-user data export jobs.
--
-- export_jobs tracks the lifecycle of a user-requested data archive:
--   pending  → background goroutine is assembling the archive
--   ready    → archive file is on disk; token URL is valid
--   downloaded → archive was successfully served at least once
--   expired  → 24-hour window passed; file deleted by cleanup worker
--   failed   → ExportUser returned an error; error_msg is set
--
-- token_hash stores SHA-256(raw_token) so the raw token only ever lives
-- in the user's email inbox. A compromised DB alone cannot download archives.

CREATE TABLE export_jobs (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT        NOT NULL UNIQUE,
    status      TEXT        NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'ready', 'downloaded', 'expired', 'failed')),
    file_path   TEXT,
    error_msg   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '24 hours',
    ready_at    TIMESTAMPTZ
);

CREATE INDEX idx_export_jobs_user_id    ON export_jobs(user_id);
CREATE INDEX idx_export_jobs_token_hash ON export_jobs(token_hash);
