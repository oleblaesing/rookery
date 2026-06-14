ALTER TABLE domains
    ADD COLUMN verification_token      TEXT,
    ADD COLUMN verification_expires_at TIMESTAMPTZ,
    ADD COLUMN verification_checked_at TIMESTAMPTZ,
    -- NULL = auto-schedule (testing 48h → enforce); 'testing'/'enforce' override
    -- it; 'disabled' 404s the MTA-STS policy endpoint.
    ADD COLUMN mta_sts_mode            TEXT
                   CHECK (mta_sts_mode IN ('testing', 'enforce', 'disabled')),
    ADD COLUMN mta_sts_id              TEXT,
    ADD COLUMN mta_sts_mode_changed_at TIMESTAMPTZ,
    ADD COLUMN catch_all_enabled       BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN catch_all_address_id    UUID REFERENCES addresses(id) ON DELETE SET NULL,
    ADD COLUMN dns_last_checked_at     TIMESTAMPTZ,
    ADD COLUMN dns_status              JSONB;

-- Index for the MTA-STS background worker (finds domains needing mode upgrade).
CREATE INDEX idx_domains_mta_sts_upgrade
    ON domains(mta_sts_mode_changed_at)
    WHERE mta_sts_mode IS NULL AND verified_at IS NOT NULL;

-- Index for drift detection (all verified non-primary domains).
CREATE INDEX idx_domains_verified_custom
    ON domains(dns_last_checked_at)
    WHERE is_primary = FALSE AND verified_at IS NOT NULL;

ALTER TABLE addresses
    ADD COLUMN is_reserved      BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN delivery_method  TEXT    NOT NULL DEFAULT 'direct'
                CHECK (delivery_method IN ('direct', 'alias', 'catch_all', 'plus_tag'));
