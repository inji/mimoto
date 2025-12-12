# Verifiable Credentials Status check

This design document outlines the approach for implementing status checks for Verifiable Credentials (VCs) within our system. The goal is to ensure that the status of a VC can be verified efficiently and securely, allowing relying parties to determine whether a credential is valid, revoked, or suspended.

### Overview

W3C Data model 2.0 supports status checking for Verifiable Credentials through the use of a `credentialStatus` property. This property points to a status list that can be queried to determine the current status of the credential.

### High level user flow

#### Flow 1 : User lands on Inji Web application and views stored VCs with their status

- User logs in to Inji Web application
- Navigates to 'Stored Cards' section
- API calls to fetch stored VCs and their stored 'Status'
- The system checks if the enough time has passed since the last status check (e.g., 24 hours)
- If enough time has elapsed (as per configuration), the system marks wallet as eligible for status check in `vc_status_check_tracker` table - if not already marked
- If enough time has not elapsed, the system skips the status check for that wallet
- For each eligible wallet, the system retrieves the stored VCs and status from the database

Sequence Diagram:

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant InjiWeb as Inji Web Wallet
    participant Mimoto
    participant Database as Database(PostgreSQL)

    User->>InjiWeb: Logs in
    InjiWeb->>Mimoto: Authorize user
    Mimoto-->> InjiWeb: Authorization response [success]
    User->>InjiWeb: Check stored cards
    InjiWeb->>Mimoto: GET wallets/{walletId}/credentials
    Mimoto->>Database: Fetch credentials for the walletId
    Database-->>Mimoto: User's credentials

    alt time elapsed since last status refresh > configured threshold
        Mimoto->>Database: Mark the wallet as eligible for status check <br /> vc_status_check_tracker
    end
    Mimoto->>InjiWeb: Return credentials with stored statuses
    InjiWeb->>User: Show credentials to user
```    

#### Flow 2 : User tries to check status of stored VCs manually

- User logs in to Inji Web application
- Navigates to 'Stored Cards' section
- User selects a specific VC to check its status
- Inji Web application sends a request to Mimoto API to check the status of the selected VC
- Mimoto check if threshold time has passed since last status check for the wallet
- If within credential-level status check limit, Mimoto proceeds to check the status of the VC immediately
- If not, Mimoto returns the last known status of the VC from database without performing a new check
- In case of any error during status check, Mimoto pushes the credential to check status queue for later processing, updates the status as 'PENDING' in the database and returns the same.

Sequence Diagram:

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant InjiWeb as Inji Web Wallet
    participant Mimoto
    participant VCVerifier as VC Verifier library
    participant Database as Database(PostgreSQL)
    participant Issuer

    User->>InjiWeb: Logs in
    InjiWeb->>Mimoto: Authorize user
    Mimoto-->> InjiWeb: Authorization response [success]
    User->>InjiWeb: Check stored cards
    InjiWeb->>Mimoto: GET wallets/{walletId}/credentials
    Mimoto->>Database: Fetch credentials for the walletId
    Database-->>Mimoto: User's credentials

    alt time elapsed since last status refresh > configured threshold
        Mimoto->>Database: Mark the wallet as eligible for status check
    end
    Mimoto->>InjiWeb: Return credentials with stored statuses
    InjiWeb->>User: Show credentials to user
    User->>InjiWeb: Select 'Check card status' option for a credential
    InjiWeb->>Mimoto: GET wallets/{walletId}/credentials/{credentialId}/status
    Mimoto->>Database: fetch credential record using credentialId
    Database-->>Mimoto: credential record
    alt time elapsed since last status check > configured threshold
        Mimoto->>VCVerifier: getCredentialStatus
        VCVerifier->>Issuer: Get the bitstring status list
        Issuer-->>VCVerifier: Return the status list
        VCVerifier->>VCVerifier: Extract the status for the credential
        VCVerifier-->>Mimoto: Return status, error (if any)
        alt error during status check
            Mimoto->>Database: Update status as 'PENDING' in database
            Mimoto->>Mimoto: Push credential to status check queue
            Mimoto->>InjiWeb: Return status as 'PENDING' with latest 'Last checked' time
        else successful status check
            Mimoto->>Mimoto: Map VC Verifier status to Inji status
        end    
        Mimoto->>Database: Update status in database
        Mimoto->>InjiWeb: Return latest status with latest 'Last checked' time 
    else not eligible for status check
        Mimoto->>InjiWeb: Return existing status from database     
    end
    InjiWeb->>User: Display status and last checked time in Stored Cards section
```

#### Flow 3 : User adds a credential to wallet

- User logs in to Inji Web application
- Selects and adds a new verifiable credential to their wallet
- During the addition process, the system performs an immediate status check for the newly added credential using the VC Verifier library
- The system updates the status of the credential in the database based on the result of the status check
- The user is notified of the successful addition of the credential along with its current status
- The newly added credential is now available in the user's wallet with its status displayed
- In case of any error during status check, the system sets the status as 'PENDING' and queues the credential for later processing

Sequence Diagram:

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant InjiWeb as Inji Web Wallet
    participant Mimoto
    participant VCVerifier as VC Verifier library
    participant Database as Database(PostgreSQL)
    participant Issuer
    User->>InjiWeb: Logs in
    InjiWeb->>Mimoto: Authorize user
    Mimoto-->> InjiWeb: Authorization response [success]
    User->>InjiWeb: Select a credential, authenticate and add to wallet
    InjiWeb->>Mimoto: POST wallets/{walletId}/credentials
    Mimoto->>VCVerifier: verifyAndGetCredentialStatus
    VCVerifier->>VCVerifier: verify the credential
    alt credential is valid
        VCVerifier->>Issuer: Get the status from issuer for data model 2.0 VCs
        Issuer->>VCVerifier: status
        VCVerifier->>VCVerifier: process the status
        VCVerifier-->>Mimoto: isValid, status
        Mimoto->>Database: Store credential with status in verifiable_credential table
        Database-->>Mimoto: Acknowledgement of storage
        Mimoto-->>InjiWeb: Success
        InjiWeb-->User: Show success message, land the user on stored card page
    else credential is invalid
        Mimoto-->>InjiWeb: Error
        InjiWeb-->User: Show error message to the user, land the user on stored card page
    end
```

### Batching Job for status checks

To optimize performance and reduce the number of external calls to issuers, the system will implement batching logic for status checks. When multiple credentials from the same issuer need to be checked, the system will group these requests and perform a single batch status check.

#### Batching Flow
Select a batch of credentials for status check, with batch size configurable via system settings. Sort credential records by \`created_at\` timestamp in ascending order. 
- For each credential in the wallet/credential record:
  - Check if the time elapsed since the last status check exceeds the configured threshold. If not, skip to the next credential.
  - If eligible for status check:
    - Retrieve the credential record from the database and decrypt the credential data.
    - Invoke the VC Verifier library to perform the status check on the credential.
    - Update the status in \`verifiable_credential\` table.
    - If an error occurs during processing, log the error and continue with the next record without updating the status.
    - After processing the batch, update the \`vc_status_check_tracker\` table to reflect the completion of the status check for each record in the batch.

```mermaid
sequenceDiagram
autonumber
participant Mimoto as Mimoto Service
participant Database as Database(PostgreSQL)
participant VCVerifier as VC Verifier Library
participant Issuer

        Mimoto->>Database: Fetch batch of credentials (sorted by created_at ASC) as per configured size <br /> from vc_status_check_tracker table with PENDING status
        Database-->>Mimoto: Return batch of tracker records
        
        loop For each credential in wallet/credential record
            alt time elapsed since last status check > configured threshold
                Mimoto->>Mimoto: Decrypt credential data
                Mimoto->>VCVerifier: getCredentialStatus(credential)
                VCVerifier->>Issuer: Get bitstring status list
                Issuer-->>VCVerifier: Return status list
                VCVerifier->>VCVerifier: Extract status for credential
                VCVerifier-->>Mimoto: Return status, error (if any)
                
                alt Successful status check
                    Mimoto->>Database: Update verifiable_credential table
                else Error during processing
                    Mimoto->>Mimoto: Log error
                    Note over Mimoto: Continue to next credential without updating status
                end
             else Not eligible for status check
                Note over Mimoto: Skip credential 
             end   
        end
        Mimoto->>Database: Update vc_status_check_tracker table
```

### API Contract

#### Fetch All Credentials with Status

`GET wallets/{walletId}/credentials`

**Description**: Retrieves all verifiable credentials stored in a specific wallet along with their current status.

**Path Parameters**:
- `walletId` (string, required): Unique identifier of the wallet

**Response**:

Two new fields to be added in the response payload:
- `status` (string): Current status of the credential (e.g., VALID, REVOKED, EXPIRED, PENDING)
- `lastCheckedAt` (string, ISO 8601 format): Timestamp of the last status check performed for the credential

**Success (200 OK)**:
```json
[
  {
    "issuerDisplayName": "Mosip",
    "issuerLogo": "https://example.com/logo.png",
    "credentialTypeDisplayName": "National Identity Department Mosip",
    "credentialTypeLogo": "https://example.com/credential-logo.png",
    "credentialId": "1234567890",
    "status": "VALID",
    "lastCheckedAt": "2025-12-11T10:30:00Z"
  }
]
```

#### Check Credential Status

**Endpoint**: `GET /wallets/{walletId}/credentials/{credentialId}/status`

**Description**: Retrieves the current status of a specific credential. Performs a fresh status check if the configured threshold time has elapsed since the last check, otherwise returns cached status from database.

**Path Parameters**:
- `walletId` (string, required): Unique identifier of the wallet
- `credentialId` (string, required): Unique identifier of the credential

**Response**:

**Success (200 OK)**:
```json
{
  "credentialId": "string",
  "status": "VALID | REVOKED | EXPIRED | PENDING",
  "lastCheckedAt": "2024-12-11T10:30:00Z",
  "isFreshCheck": true,
  "message": "string (optional)"
}
```

**Response Fields**:
- `credentialId`: The unique identifier of the credential
- `status`: Current status of the credential
  - `VALID`: Credential is active and valid
  - `REVOKED`: Credential has been revoked by issuer
  - `EXPIRED`: Credential has expired
  - `PENDING`: Status check is queued or in progress
- `lastCheckedAt`: Timestamp of the most recent status check
- `isFreshCheck`: Boolean indicating whether this response contains freshly checked status (`true`) or cached status from database (`false`)
- `message`: Optional message providing additional context (e.g., error details when status is PENDING)

**Error Responses**:

- **404 Not Found**: Credential or wallet not found
```json
{
  "errorCode": "CREDENTIAL_NOT_FOUND",
  "message": "Credential with ID {credentialId} not found for wallet {walletId}"
}
```

- **400 Bad Request**: Invalid request parameters
```json
{
  "errorCode": "INVALID_REQUEST",
  "message": "Invalid walletId or credentialId format"
}
```

- **500 Internal Server Error**: Unexpected error during status check
```json
{
  "errorCode": "INTERNAL_SERVER_ERROR",
  "message": "An unexpected error occurred while checking credential status"
}
```

**Behavior Notes**:
- If threshold time hasn't elapsed since last check, returns cached status with `isFreshCheck: false`
- If threshold time has elapsed, performs fresh status check and returns with `isFreshCheck: true`
- If fresh status check fails, returns status as `PENDING` with `isFreshCheck: true` and queues credential for batch processing
- The `lastCheckedAt` timestamp always reflects when the status was actually last verified with the issuer

### Database Schema

#### verifiable_credential Table

This table stores the verifiable credentials along with their status information. Two columns to be introduced for status tracking : 

| Column Name            | Data Type   | Description                                                                 |
|------------------------|-------------|-----------------------------------------------------------------------------|
| status                 | VARCHAR(20) | Current status of the credential (e.g., VALID, REVOKED, SUSPENDED, PENDING) |
| status_last_checked_at | TIMESTAMP   | Timestamp of the last status check performed                                |

Possible values for `status` column:
- `VALID`: Credential is active and valid, applicable for all type of VCs. 
- `REVOKED`: Credential has been revoked by issuer, applicable for only W3C Data model 2.0 VCs with status list support.
- `EXPIRED`: Credential is expired, applicable for all type of VCs.
- `PENDING`: Status check is queued for retry.

#### vc_status_check_tracker Table

This table tracks the status check operations for verifiable credentials.

| Column Name     | Data Type   | Description                                                                         |
|-----------------|-------------|-------------------------------------------------------------------------------------|
| wallet_id       | VARCHAR(36) | Unique identifier for the wallet                                                    |
| credential_id   | VARCHAR(36) | Unique identifier for the credential                                                |
| issuer_id       | VARCHAR(50) | Identifier of the credential issuer                                                 |
| credential_type | VARCHAR(50) | Type of the credential                                                              |
| run_status      | VARCHAR(20) | Current status of the status check run. Two possible status: `PENDING`, `COMPLETED` |
| created_at      | TIMESTAMP   | Timestamp when the record was created                                               |
| completed_at    | TIMESTAMP   | Timestamp when the status check was completed                                       |

### Migration of existing credentials

A one-time migration script will be executed to initialize the `status` and `status_last_checked_at` fields for existing credentials in the `verifiable_credential` table. The script will set the initial status to `PENDING` and the `status_last_checked_at` to the current timestamp, indicating that these credentials need to be checked for their status during the next scheduled batch job or manual check.
