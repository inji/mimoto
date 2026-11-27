ALTER TABLE verifiable_credentials
    DROP COLUMN IF EXISTS is_expired,
    DROP COLUMN IF EXISTS status_last_checked_at,
    DROP COLUMN IF EXISTS status_checks;
