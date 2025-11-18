-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_mimoto
-- Table Name : trusted_verifiers
-- Purpose    : To store the verifiers details Which are trusted by the Wallet User
--
-- Create By   	: Bhargavi Puvvada
-- Created Date	: 09-Sep-2025
--
-- Modified Date        Modified By         Comments / Remarks
-- 07-Oct-2025          Durgesh Konga       Added verifiable_presentations table to make it backward compatibility
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

--- Create table for trusted_verifiers

CREATE TABLE IF NOT EXISTS trusted_verifiers (
    id character varying(36) PRIMARY KEY,  -- Primary key for the table
    wallet_id character varying(36) NOT NULL,  -- Foreign key referring to the wallet table (wallet.id)
    verifier_id character varying(255) NOT NULL,  -- Stores the unique identifier (client_id) of the trusted verifier
    created_at TIMESTAMP DEFAULT now()  -- Timestamp of record creation (defaults to current time)
    );

-- Add comments for documentation
COMMENT ON TABLE trusted_verifiers IS 'Trusted Verifiers: Contains information about verifiers trusted by a user''s wallet';

COMMENT ON COLUMN trusted_verifiers.id IS 'Primary Key: Unique identifier for the trusted verifier record';
COMMENT ON COLUMN trusted_verifiers.wallet_id IS 'Wallet ID: Foreign key referring to the wallet table, linking the verifier to a specific wallet';
COMMENT ON COLUMN trusted_verifiers.verifier_id IS 'Verifier ID: Unique identifier (client_id) of the trusted verifier';
COMMENT ON COLUMN trusted_verifiers.created_at IS 'Created At: The date and time when the trusted verifier record was created';

-- Create table for verifiable_presentations

CREATE TABLE IF NOT EXISTS verifiable_presentations (
    id character varying(36) PRIMARY KEY,
    wallet_id character varying(36) NOT NULL,
    auth_request JSONB NOT NULL,
    presentation_data JSONB NOT NULL,
    verifier_id character varying(255),
    status character varying(32) NOT NULL,
    requested_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT now(),
    consent BOOLEAN NOT NULL DEFAULT TRUE
);
COMMENT ON TABLE verifiable_presentations IS 'Verifiable Presentations: Records of presentations shared with verifiers';
COMMENT ON COLUMN verifiable_presentations.id IS 'Primary Key: Unique identifier for the presentation (presentationId)';
COMMENT ON COLUMN verifiable_presentations.wallet_id IS 'Wallet ID: Foreign key referring to the wallet table';
COMMENT ON COLUMN verifiable_presentations.auth_request IS 'Authorization Request: The authorization request payload from the verifier';
COMMENT ON COLUMN verifiable_presentations.presentation_data IS 'Presentation Data: Additional metadata including shared credential ids';
COMMENT ON COLUMN verifiable_presentations.verifier_id IS 'Verifier Identifier: The verifier''s client_id or equivalent identifier';
COMMENT ON COLUMN verifiable_presentations.status IS 'Status: in-progress/success/error';
COMMENT ON COLUMN verifiable_presentations.requested_at IS 'Requested At: Timestamp when verifier requested the presentation';
COMMENT ON COLUMN verifiable_presentations.created_at IS 'Created At: Timestamp when the submission record was created';
COMMENT ON COLUMN verifiable_presentations.consent IS 'Consent: Indicates whether user consented to sharing';
