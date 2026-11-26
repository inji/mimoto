ALTER TABLE verifiable_credentials
    ADD COLUMN IF NOT EXISTS status_checks JSONB;

ALTER TABLE verifiable_credentials
    ADD COLUMN IF NOT EXISTS status_last_checked_at TIMESTAMP;

ALTER TABLE verifiable_credentials
    ADD COLUMN IF NOT EXISTS is_expired BOOLEAN;

COMMENT ON COLUMN verifiable_credentials.status_checks IS 'Status checks: Stores the last known status of the credential, including revocation or suspension status, represented by purpose and status value';
COMMENT ON COLUMN verifiable_credentials.status_last_checked_at IS 'Status Last Checked At: Time at which the credential status was last verified';
COMMENT ON COLUMN verifiable_credentials.is_expired IS 'Is Expired: Whether the credential was expired at the last check. NULL when expiry has not been checked';
