# Wallet Unlock Process with max limit on failed attempts

## Overview

The Wallet Unlock feature provides a secure mechanism to access a user's encrypted wallet using their PIN. This process includes sophisticated security measures such as temporary and permanent locking mechanisms to prevent brute force attacks, along with PIN-based decryption of wallet key. The unlock flow is triggered when a user needs to access their wallet after session expiry or initial login.

## Key Features

- PIN-based wallet unlocking
- Progressive security with temporary and permanent locking
- Configurable failed attempt limits and lock cycles
- Automatic lock expiry for temporary locks
- Session-based wallet key storage
- Last attempt warning before permanent lockout

## Sequence Diagram

The sequence diagram below illustrates the complete unlock process, including validation, PIN verification, and lock management steps.

```mermaid
sequenceDiagram
actor Client
participant WalletsController
participant WalletService
participant WalletUnlockService
participant WalletLockService
participant WalletLockStatusUtils
participant WalletUtil
participant WalletRepository

    Client->>WalletsController: POST /wallets/{walletId}/unlock
    activate WalletsController
    
    WalletsController->>WalletService: unlockWallet(walletId, pin, userId)
    activate WalletService
    
    WalletService->>WalletService: validateUserId & validateWalletPin
    WalletService->>WalletRepository: findByUserIdAndId(userId, walletId)
    activate WalletRepository
    WalletRepository-->>WalletService: Returns Wallet object
    deactivate WalletRepository
    
    WalletService->>WalletUnlockService: handleUnlock(wallet, pin)
    activate WalletUnlockService
    
    WalletUnlockService->>WalletLockService: resetTemporaryLockIfExpired(wallet)
    activate WalletLockService
    Note over WalletLockService: Checks if Wallet is temporarily locked before and that lock has expired (if retryBlockedUntil in milliseconds from Database > Current System time in milliseconds),<br/> then it resets the failedAttemptCount and retryBlockedUntil to their defaults and sets the walletLockStatus = lock_expired
    WalletLockService-->>WalletUnlockService: Returns updated Wallet
    deactivate WalletLockService
    
    WalletUnlockService->>WalletUnlockService: throwExceptionIfWalletIsLocked(wallet)
    
    WalletUnlockService->>WalletLockStatusUtils: getErrorBasedOnWalletLockStatus(wallet)
    activate WalletLockStatusUtils
    WalletLockStatusUtils-->>WalletUnlockService: Returns ErrorDTO
    deactivate WalletLockStatusUtils
    
    alt Wallet is locked Temporarily or Permanently
        WalletUnlockService-->>WalletService: Throws WalletLockedException
    else Wallet is not locked
        WalletUnlockService->>WalletUtil: decryptWalletKey(walletKey, pin)
        activate WalletUtil
        alt Successful PIN Decryption
            WalletUtil-->>WalletUnlockService: Returns decryptedWalletKey

            WalletUnlockService->>WalletLockService: resetLockState(wallet)
            activate WalletLockService
            Note over WalletLockService: Resets all lock counters,<br/>retryBlockedUntil and status to default values
            WalletLockService-->>WalletUnlockService: Returns updated Wallet
            deactivate WalletLockService
            
            WalletUnlockService->>WalletRepository: save(wallet)
            activate WalletRepository
            deactivate WalletRepository
            WalletUnlockService-->>WalletService: Returns decryptedWalletKey
        else Invalid PIN
            WalletUtil-->>WalletUnlockService: Throws InvalidRequestException
            deactivate WalletUtil
            WalletUnlockService->>WalletUnlockService: handleFailedUnlock(wallet)
            
            WalletUnlockService->>WalletLockService: enforceLockCyclePolicy(wallet)
            activate WalletLockService
            Note over WalletLockService:1. Increments failedAttemptCount & <br/>2. if currentCycleCount = 0 (means this is the first failed attempt made in all cycles), it sets currentCycleCount = 1<br/>3. If failedAttemptCount = maxFailedAttemptsAllowedPerCycle then increments currentCycleCount<br/>4. If currentCycleCount > maxLockCyclesAllowed then sets walletLockStatus = permanently_locked & retryBlockedUntil = null <br/> else sets walletLockStatus = temporarily_locked & and retryBlockedUntil = Current System time (in milliseconds) + retryBlockedUntil (in milliseconds) value from config properties file<br/>5. If failedAttemptCount = maxFailedAttemptsAllowedPerCycle - 1 & currentCycleCount = maxLockCyclesAllowed then sets <br/> walletLockStatus = last_attempt_before_lockout
            WalletLockService-->>WalletUnlockService: Returns updated Wallet
            deactivate WalletLockService
            
            WalletUnlockService->>WalletUnlockService: throwExceptionIfLastAttemptLeftForUnlock(wallet)
            
            WalletUnlockService->>WalletLockStatusUtils: getErrorBasedOnWalletLockStatus(wallet)
            activate WalletLockStatusUtils
            WalletLockStatusUtils-->>WalletUnlockService: Returns ErrorDTO
            deactivate WalletLockStatusUtils
            
            alt if errorCode is last_attempt_before_lockout
                WalletUnlockService-->>WalletService: Throws InvalidRequestException
            else otherwise
                WalletUnlockService->>WalletLockService: resetTemporaryLockIfExpired(wallet)
                activate WalletLockService
                Note over WalletLockService: Checks if Wallet is temporarily locked before and that lock has expired (if retryBlockedUntil in milliseconds from Database  > Current System time in milliseconds),<br/> then it resets the failedAttemptCount and retryBlockedUntil to their defaults and sets the walletLockStatus = lock_expired
                WalletLockService-->>WalletUnlockService: Returns updated Wallet
                deactivate WalletLockService
                
                WalletUnlockService->>WalletUnlockService: throwExceptionIfWalletIsLocked(wallet)
                WalletUnlockService->>WalletLockStatusUtils: getErrorBasedOnWalletLockStatus(wallet)
                activate WalletLockStatusUtils
                WalletLockStatusUtils-->>WalletUnlockService: Returns ErrorDTO
                deactivate WalletLockStatusUtils
                alt Wallet is locked Temporarily or Permanently
                    WalletUnlockService-->>WalletRepository: save(wallet)
                    activate WalletRepository
                    deactivate WalletRepository
                    WalletUnlockService-->>WalletService: Throws WalletLockedException
                else Wallet is not locked
                    WalletUnlockService-->>WalletRepository: save(wallet)
                    activate WalletRepository
                    deactivate WalletRepository
                    deactivate WalletUnlockService
                end
            end
        end
    end
    
    WalletService-->>WalletsController: Returns WalletResponseDto or throws Exception
    deactivate WalletService

    alt Success Response
        WalletsController->>WalletsController: Stores wallet_id & received decryptedWalletKey as wallet_key into Http session
        WalletsController-->>Client: Returns 200 OK status with WalletResponseDto
    else Error Response
        WalletsController-->>Client: Returns Error status with ErrorDTO
    end
    deactivate WalletsController
```
## Configuration

Configurable properties that govern the entire Passcode flow within the Wallet unlock process are defined in the
`application-default.properties` file for the local setup, and in the `mimoto-default.properties` file for the environment setup.

#### Passcode Control Properties
- `wallet.passcode.retryBlockedUntil`: Duration for which the Wallet remains in temporary lock state (in milliseconds)
- `wallet.passcode.maxFailedAttemptsAllowedPerCycle`: Maximum number of failed attempts allowed before triggering a temporary lock cycle
- `wallet.passcode.maxLockCyclesAllowed`: Maximum lock cycles allowed before permanent lockout

```properties
# Duration (in minutes) for which the wallet remains locked after exceeding failed attempts in a cycle.
# Must be a whole number; decimal/fractional values (e.g., 0.5) will throw an error during Mimoto launch
wallet.passcode.retryBlockedUntil=60
# Maximum number of failed passcode attempts allowed in a single cycle (defaults to 1 if <=0)
wallet.passcode.maxFailedAttemptsAllowedPerCycle=5
# Maximum number of lock cycles allowed before the wallet is permanently locked (defaults to 1 if <=0)
wallet.passcode.maxLockCyclesAllowed=3
```

## Errors

Mimoto uses the following error codes to signal wallet state and failures to the UI:

| Error Code                    | HTTP Status | Description                                                                                          |
|-------------------------------|-------------|------------------------------------------------------------------------------------------------------|
| `invalid_request`             | 400         | Invalid input such as missing user ID, invalid wallet ID, wallet not found, or invalid PIN format    |
| `invalid_pin`                 | 400         | Incorrect PIN, retry attempts are still available.                                                   |
| `last_attempt_before_lockout` | 400         | Indicates the final remaining retry attempt before the wallet transitions to a permanent lock state. |
| `unauthorized`                | 401         | User is not authenticated or user ID is missing from the session.                                    |
| `temporarily_locked`          | 423         | Maximum attempts reached; wallet locked temporarily until cooldown period expires.                   |
| `permanently_locked`          | 423         | Maximum lock cycles exceeded; wallet is permanently locked and cannot be unlocked using PIN.         |
| `internal_server_error`       | 500         | Unexpected server-side failure during wallet decryption or retrieval.                                |
| `database_unavailable`        | 503         | Failure to connect to or interact with the database.                                                 |