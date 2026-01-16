# Verifiable Credentials Status check

This design document outlines the approach for implementing status checks for Verifiable Credentials (VCs) within our system. The goal is to ensure that the status of a VC can be verified efficiently and securely, allowing relying parties to determine whether a credential is valid, revoked, or suspended.

### Overview

W3C Data model 2.0 supports status checking for Verifiable Credentials through the use of a `credentialStatus` property. This property points to a status list that can be queried to determine the current status of the credential.

### High level user flow

#### Flow : User lands on Inji Web application and views stored VCs with their status

- The user logs in and opens the Stored Cards page.
- For each credential in the wallet, mimoto will check the status using the VC verifier library. 
- For the W3C Data model 2.0 VCs, we need to pass status list credential cache data if available to the library. If cache is missing, the library should skip status list check for the credential.
- The status returned by the library will be stored in the database and shown to the user alongside each credential. The last checked time will be updated to the time at which status list cache was created - if there are multiple list involved then minimum time will be updated in the database. 
- If there are multiple status list credentials involved for a VC, all the status list should be available in the cache for status list check to be performed. If any one of them is missing, status list check will be skipped for that VC.
- For credentials that were added before migrating to the latest application, their status will be set to valid by default using a database migration script.
- The status will be returned as an array. Mimoto will return all applicable status purposes for a credential as-is, without any transformation. Converting these into user-friendly labels will be handled by Inji Web.
- If status list is not applicable for a credential, only schema validation and signature verification results will be returned based on the validity period of the credential. The last checked time will be updated to current time for the credentials in this case.
- The applicable check is already done by the VC Verifier library based on the credential type and data model version, no additional logic is needed in Mimoto for this.

Sequence Diagram:

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant InjiWeb as Inji Web Wallet
    participant Mimoto
    participant Database as Database(PostgreSQL)
    participant VCVerifier as VC Verifier

    User->>InjiWeb: Logs in
    InjiWeb->>Mimoto: Authorize user
    Mimoto-->> InjiWeb: Authorization response [success]
    InjiWeb-->>User: Land the user on home page
    User->>InjiWeb: Check stored cards
    InjiWeb->>Mimoto: GET wallets/{walletId}/credentials
    Mimoto->>Database: Fetch credentials for the walletId
    Database-->>Mimoto: User's credentials along with the status
    loop for each credential
        Mimoto->>Mimoto: check if status list check is applicable, fetch bitstring status list cache(s) applicable for the credential
        alt if credential status list check is applicable and bitstring status list cache exists for credential
            Mimoto->>VCVerifier: verifyAndGetCredentialStatus, input - credential, bitstring status list cache array
            VCVerifier->>VCVerifier: validate and verify the credential, extract the status(s) from the bitstring array
            VCVerifier-->>Mimoto: verification result, status(s)
            Mimoto->>Database: update status details in database
            Database-->>Mimoto: success
        else if credential status list is not applicable or bitstring status list cache missing (or partially available)
            Mimoto->>VCVerifier:  verify, input - credential
            VCVerifier->>VCVerifier: validate and verify the credential
            VCVerifier-->>Mimoto: verification result
            Mimoto->>Database: update status details in database
            Database-->>Mimoto: success
        end
    end
    Mimoto->>InjiWeb: Return credentials with stored statuses
    InjiWeb->>User: Show credentials to user
```

#### Flow : User clicks on 'Check card status' option for a credential
- The user selects the 'Check card status' option for a specific credential in their wallet.
- Mimoto invokes the VC Verifier library to check the status of the credential. Finally updates the status details in the database.
- Mimoto updates the status list cache too with the latest status list credential received from the issuer.
- Last checked time is updated to the current time for the credential.

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
    Mimoto->>InjiWeb: Return credentials with stored statuses
    InjiWeb->>User: Show credentials to user
    User->>InjiWeb: Select 'Check card status' option for a credential
    InjiWeb->>Mimoto: GET wallets/{walletId}/credentials/{credentialId}/status
    Mimoto->>Database: fetch credential record using credentialId
    Database-->>Mimoto: credential record
    alt status list check applicable for the credential
        Mimoto->>VCVerifier: getCredentialStatus
        VCVerifier->>Issuer: Get the bitstring status list
        Issuer-->>VCVerifier: Return the status list credential
        VCVerifier->>VCVerifier: Extract the status for the credential
        VCVerifier-->>Mimoto: Return status, status list credential(s), error (if any)
    else status list check not applicable for the credential
        Mimoto->>VCVerifier: verify
        VCVerifier->>VCVerifier: validate and verify the credential
        VCVerifier-->>Mimoto: Return verification result, error (if any)
    end
    alt error during status check
        Mimoto->>InjiWeb: Return error without updating status in database
        InjiWeb->>User: Display error message to user
    else successful status check
        Mimoto->>Database: Update status in database
        Database-->>Mimoto: Acknowledgement of update
        Mimoto->>Mimoto: Update status list credential cache with latest status list
        Mimoto->>InjiWeb: Return latest status with latest 'Last checked' time
        InjiWeb->>User: Display status and last checked time in Stored Cards section
    end
```

#### Flow 3 : User adds a credential to wallet

- User logs in to Inji Web application
- Selects and adds a new verifiable credential to their wallet
- During the addition process, the system performs an immediate status check for the newly added credential using the VC Verifier library
- The system updates the status of the credential in the database based on the result of the status check and caches the status list
- The user is notified of the successful addition of the credential along with its current status
- The newly added credential is now available in the user's wallet with its status displayed
- If any error during status check, the user is notified with an error message and the credential is not added to the wallet.

Sequence Diagram:

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant InjiWeb as Inji Web Wallet
    participant Mimoto
    participant VCVerifier as VC Verifier library
    participant Database as Database(PostgresSQL)
    participant Issuer
    User->>InjiWeb: Logs in
    InjiWeb->>Mimoto: Authorize user
    Mimoto-->> InjiWeb: Authorization response [success]
    User->>InjiWeb: Select a credential, authenticate and add to wallet
    InjiWeb->>Mimoto: POST wallets/{walletId}/credentials
    Mimoto->>VCVerifier: verifyAndGetCredentialStatus
    VCVerifier->>VCVerifier: verify the credential
    alt credential is valid
        alt status list check applicable for the credential
            VCVerifier->>Issuer: Get the status list credential from issuer for data model 2.0 VCs
            Issuer-->>VCVerifier: status list credential
            VCVerifier->>VCVerifier: process the status list and extract status for the credential
            VCVerifier-->>Mimoto: isValid, status, status list credential, error(if any)
            Mimoto->>Database: Store credential with status details in verifiable_credential table
            Database-->>Mimoto: Acknowledgement of storage
            Mimoto->>Mimoto: Update status list credential cache with status list credential(s)
            Mimoto-->>InjiWeb: Success
            InjiWeb-->User: Show success message, land the user on stored card page
        else status list check not applicable for the credential
            VCVerifier-->>Mimoto: isValid, error(if any)
            Mimoto->>Database: Store credential with status in verifiable_credential table
            Database-->>Mimoto: Acknowledgement of storage
            Mimoto-->>InjiWeb: Success
            InjiWeb-->User: Show success message, land the user on stored card page
        end
    else credential is invalid
        Mimoto-->>InjiWeb: Error
        InjiWeb-->User: Show error message to the user
    end
```

### API Contract

#### Fetch All Credentials with Status

`GET wallets/{walletId}/credentials`

**Description**: Retrieves all verifiable credentials stored in a specific wallet along with their current status.

**Path Parameters**:
- `walletId` (string, required): Unique identifier of the wallet

**Response**:

Three new fields to be added in the response payload:
- `isSchemaAndSignatureValid` (boolean): Indicates if the schema and signature validation passed
- `isExpired` (boolean): Indicates if the credential has expired
- `statusChecks` (array): Array of status purposes and their validity
  - Each object in the array contains:
    - `purpose` (string): The purpose of the status check (e.g., revocation, suspension)
    - `valid` (boolean): Indicates if the credential is valid for that purpose. `true` means valid, `false` means invalid i.e. revoked, suspended, etc.
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
    "isSchemaAndSignatureValid": true,
    "isExpired": false,
    "statusChecks": [
      {"purpose": "revocation", "valid":true },
      {"purpose": "suspension", "valid":true }
    ],
    "lastCheckedAt": "2025-12-11T10:30:00Z"
  }
]
```

#### Check Credential Status

**Endpoint**: `GET /wallets/{walletId}/credentials/{credentialId}/status`

**Description**: Retrieves the current status of a specific credential from the issuer.

**Path Parameters**:
- `walletId` (string, required): Unique identifier of the wallet
- `credentialId` (string, required): Unique identifier of the credential

**Response**:

**Success (200 OK)**:
```json
{
  "credentialId": "string",
  "isSchemaAndSignatureValid": true,
  "isExpired": false,
  "statusChecks": [
    {"purpose": "revocation", "valid":true },
    {"purpose": "suspension", "valid":true }
  ],  
  "lastCheckedAt": "2024-12-11T10:30:00Z",
  "message": "string (optional)"
}
```

**Response Fields**:
- `credentialId`: The unique identifier of the credential
- `isSchemaAndSignatureValid`: Boolean indicating if the schema and signature validation passed
- `isExpired`: Boolean indicating if the credential has expired
- `statusChecks`: Array of status purposes and their validity
- Each object in the array contains:
  - `purpose`: The purpose of the status check (e.g., revocation, suspension)
  - `valid`: Boolean indicating if the credential is valid for that purpose. `true` means valid, `false` means invalid i.e. revoked, suspended, etc.
- `lastCheckedAt`: Timestamp of the most recent status check
- `message`: Optional message providing additional context, especially in case of error

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

- **424 Failed Dependency**: Dependency service error
```json
{
  "errorCode": "STATUS_CHECK_FAILED",
  "message": "Failed to check credential status due to dependency service error"
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
- The `lastCheckedAt` timestamp always reflects when the status was actually last verified with the issuer
- In case of any error during status check, the existing status in the database remains unchanged
- The status list credential cache is updated only on successful status checks

### Database Schema

#### verifiable_credential Table

This table stores the verifiable credentials along with their status information. Two columns to be introduced for status tracking : 

| Column Name               | Data Type | Nullable? | Description                                                                                                                                                                                                       |
|---------------------------|-----------|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| is_expired                | BOOLEAN   | Yes       | Indicates if the credentials has expired or not. Will be NULL for migrated credential where expired status is not known.                                                                                          |
| is_schema_signature_valid | BOOLEAN   | No        | If signature and schema validation has passed successfully.                                                                                                                                                       |
| status_checks             | JSONB     | Yes       | Current status purpose array for the credential derived from status list credential (e.g., revocation, suspension) . E.g. `[ {"purpose": "revocation", "valid":true }, {"purpose": "suspension", "valid":true }]` |
| status_last_checked_at    | TIMESTAMP | No        | Timestamp of the last status check performed                                                                                                                                                                      |

### Migration of existing credentials

A one-time migration script will be executed to initialize the `is_schema_signature_valid` and `status_last_checked_at` fields for existing credentials in the `verifiable_credential` table. The script will set the `is_schema_signature_valid` value to true and the `status_last_checked_at` to the current timestamp.


### Caching Strategy

To optimize performance and reduce redundant network calls to issuers for status checks, a caching mechanism will be implemented for status list credentials. The cache will store the status list credentials retrieved from issuers, allowing for quick access during subsequent status checks.

#### Cache Structure
The cache will be structured as follows:
- **Cache Name**: `statusListCredential`
- **Key**: `statusListId` - Unique identifier for the status list credential. The value will be value of `statusListCredential` field in `credentialStatus` object in Data model 2.0 VCs. E.g. https://injicertify-farmer.dev-int-inji.mosip.net/v1/certify/credentials/status-list/a7b3ac9a-861a-4fa3-9c85-27e79d35fad3
- **Value**:
  - `statusListCredential`: The actual bitstring retrieved from the status list credential
  - `fetchedAt`: Timestamp indicating when the status list credential was fetched
- **Expiration Policy**: Each cache entry will have a Time-To-Live (TTL) of 24 hours. After this period, the entry will be considered stale and will be refreshed upon the next status check request. This can be configured via configuration.

### VC Verifier Library modifications
- The VC Verifier library will be updated to accept an optional parameter for the status list credential cache. 
- When performing status checks, the library will first check the provided cache for the required status list credential. If found, it will use the cached version; otherwise, it will skip the status list check for that credential. 
- Existing functionality of the library will remain unchanged if no cache is provided.

#### Implementation Details
- Method signature to be modified for verifyAndGetCredentialStatus for VC Verifier library:

```kotlin
fun verifyAndGetCredentialStatus(
        credential: String,
        credentialFormat: CredentialFormat,
        statusPurposeList: List<String> = emptyList(),
        statusListCredentialCache: Map<String, StatusListCredentialCacheEntry> = emptyMap()
    ): CredentialVerificationSummary
```

- This new param will further be passed to the internal method which extracts status from status list credential(s). When this param is passed, http calls will not be made to fetch status list credential(s) from issuer.
- Existing data class `CredentialStatusResult` will be updated to return status list credential(s) as well when http calls are made to fetch status list credential(s) from issuer : 

```kotlin
data class CredentialStatusResult(
    val isValid: Boolean,
    val error: StatusCheckException?,
    val statusListCredential: JsonLDObject? = null
)
```
- The new field will be null when status list credential is fetched from cache or if its not applicable for the credential.
