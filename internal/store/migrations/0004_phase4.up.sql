-- Migration 0004: Phase 4 schema — custom domains, multi-address, drift detection.
--
-- New columns on domains:
--   verification_token      — the _rookery-challenge TXT value (ADR-0034)
--   verification_expires_at — 7-day TTL on the challenge token
--   verification_checked_at — timestamp of the last DNS check during verification
--   mta_sts_mode            — NULL (auto-schedule), 'testing', 'enforce', 'disabled'
--   mta_sts_id              — the id= field published in _mta-sts TXT (ADR-0037)
--   mta_sts_mode_changed_at — when mta_sts_mode was last changed (testing→enforce gate)
--   catch_all_enabled       — opt-in catch-all for this domain (ADR-0017)
--   catch_all_address_id    — which address receives catch-all mail
--   dns_last_checked_at     — timestamp of last drift-detection run (ADR-0038)
--   dns_status              — JSON per-record status from last drift run
--
-- New columns on addresses:
--   is_reserved             — TRUE for postmaster/abuse/hostmaster/webmaster (ADR-0018)
--   delivery_method         — 'direct' | 'alias' | 'catch_all' | 'plus_tag'
--                             for inbox display and filtering
--
-- Design notes:
--   • mta_sts_mode = NULL means "follow the auto-schedule" (testing for 48h, then
--     enforce). The application computes the effective mode from mta_sts_mode and
--     mta_sts_mode_changed_at. An explicit 'testing' or 'enforce' overrides the
--     schedule. 'disabled' suppresses the MTA-STS policy endpoint (404).
--   • catch_all_address_id references addresses(id) ON DELETE SET NULL so removing
--     the catch-all target address disables catch-all gracefully.
--   • dns_status is JSONB so it can be queried with @> operators if needed, and
--     the application can deserialise it into a typed struct.

-- -------------------------------------------------------------------------
-- domains — Phase 4 additions
-- -------------------------------------------------------------------------
ALTER TABLE domains
    ADD COLUMN verification_token      TEXT,
    ADD COLUMN verification_expires_at TIMESTAMPTZ,
    ADD COLUMN verification_checked_at TIMESTAMPTZ,
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

-- -------------------------------------------------------------------------
-- addresses — Phase 4 additions
-- -------------------------------------------------------------------------
ALTER TABLE addresses
    ADD COLUMN is_reserved      BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN delivery_method  TEXT    NOT NULL DEFAULT 'direct'
                CHECK (delivery_method IN ('direct', 'alias', 'catch_all', 'plus_tag'));
