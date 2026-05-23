-- Revert migration 0004: drop Phase 4 columns.
DROP INDEX IF EXISTS idx_domains_verified_custom;
DROP INDEX IF EXISTS idx_domains_mta_sts_upgrade;

ALTER TABLE addresses
    DROP COLUMN IF EXISTS delivery_method,
    DROP COLUMN IF EXISTS is_reserved;

ALTER TABLE domains
    DROP COLUMN IF EXISTS dns_status,
    DROP COLUMN IF EXISTS dns_last_checked_at,
    DROP COLUMN IF EXISTS catch_all_address_id,
    DROP COLUMN IF EXISTS catch_all_enabled,
    DROP COLUMN IF EXISTS mta_sts_mode_changed_at,
    DROP COLUMN IF EXISTS mta_sts_id,
    DROP COLUMN IF EXISTS mta_sts_mode,
    DROP COLUMN IF EXISTS verification_checked_at,
    DROP COLUMN IF EXISTS verification_expires_at,
    DROP COLUMN IF EXISTS verification_token;
