-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_mimoto
-- Table Name : verifiable_credentials
-- Purpose    : Stores verifiable credentials related to the user, encrypted with wallet_key
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS verifiable_credentials (
    id character varying(36) PRIMARY KEY,  -- Primary key for the table
    wallet_id character varying(36) NOT NULL,  -- Foreign key referring to the wallet table (wallet.id)
    credential TEXT NOT NULL,  -- Encrypted credential (using wallet_key for encryption/decryption)
    credential_metadata JSONB NOT NULL,  -- Metadata about the credential
    status_checks JSONB,  -- Status purposes such as revocation and suspension
    status_last_checked_at TIMESTAMP,  -- Time of the last status check; NULL until checked
    is_expired BOOLEAN,  -- Whether the credential was expired at the last check; NULL until checked
    created_at TIMESTAMP DEFAULT now(),  -- Timestamp of record creation (defaults to current time)
    updated_at TIMESTAMP DEFAULT now(),  -- Timestamp of last update (defaults to current time)

    CONSTRAINT fk_wallet_id FOREIGN KEY (wallet_id) REFERENCES wallet (id) ON DELETE CASCADE
);

COMMENT ON TABLE verifiable_credentials IS 'Verifiable Credentials: Contains user credentials, encrypted using wallet key';
COMMENT ON COLUMN verifiable_credentials.id IS 'Primary Key: Unique identifier for the verifiable credential record';
COMMENT ON COLUMN verifiable_credentials.wallet_id IS 'Wallet ID: Foreign key referring to the wallet table, linked to the user''s wallet';
COMMENT ON COLUMN verifiable_credentials.credential IS 'Credential: Encrypted credential using the wallet''s key';
COMMENT ON COLUMN verifiable_credentials.credential_metadata IS 'Credential Metadata: Additional information about the credential (e.g., issuer, claims)';
COMMENT ON COLUMN verifiable_credentials.status_checks IS 'Status Checks: Stores the results of credential status checks, such as revocation or suspension, along with their respective purposes';
COMMENT ON COLUMN verifiable_credentials.status_last_checked_at IS 'Status Last Checked At: Time at which the credential status was last verified';
COMMENT ON COLUMN verifiable_credentials.is_expired IS 'Is Expired: Whether the credential was expired at the last check. NULL when expiry has not been checked';
COMMENT ON COLUMN verifiable_credentials.created_at IS 'Created At: The date and time when the credential was created';
COMMENT ON COLUMN verifiable_credentials.updated_at IS 'Updated At: The date and time when the credential was last updated';
