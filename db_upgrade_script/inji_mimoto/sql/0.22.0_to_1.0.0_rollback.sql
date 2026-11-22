ALTER TABLE verifiable_credentials
    DROP COLUMN IF EXISTS is_expired;

ALTER TABLE verifiable_credentials
    DROP COLUMN IF EXISTS status_last_checked_at;

ALTER TABLE verifiable_credentials
    DROP COLUMN IF EXISTS status_checks;
