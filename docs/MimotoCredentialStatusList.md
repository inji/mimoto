# Credential status list at download — Mimoto design

**Issue:** [inji-wallet#2606](https://github.com/inji/inji-wallet/issues/2606)  
**Components:** Mimoto, `vc-verifier`  
**Date:** 22 November 2026

Wallet checks the Attestation Status List (ASL) when a credential is downloaded, and can refresh that check later for a stored credential. `vc-verifier` parses the status pointer, GETs the status URI, validates the CWT, and returns a purpose map. Mimoto calls that library once, stores the map, and only fails the wallet when the list cannot be checked.

## Scope

| In this design | Out of scope |
|---|---|
| Status check on wallet download (`storeDownloadedCredential`) | Caching / ttl reuse of the CWT |
| Same library call on guest PDF (`generateCredentialPdf`) | ARL |
| Persist `statusChecks` / `statusLastCheckedAt` / `isExpired` on the wallet row | Issuer publishing of status lists |
| Status purposes from `mosip.inji.credential.status.purpose-list` | OpenID4VP / Share |
| Refresh status for a stored credential (`GET .../credentials/{id}/status`) | |

## 1. Who does what

| Component | Owns | Does not do |
|---|---|---|
| `vc-verifier` | Crypto, read MSO `{uri, idx}`, GET the CWT, validate CWT, read the bit, return a purpose map | Wallet policy, DB store, Inji Web copy |
| Mimoto | Call the library after OpenID4VCI; persist the returned map; wallet vs guest policy | Parse CBOR / CWT itself |
| Inji Web | Show stored status (`valid` per purpose, `isExpired`) or retry on unavailable | Fetch or interpret the status list |

HTTP for the status URI lives inside `vc-verifier` (`NetworkManagerClient.sendHTTPRequestBytes`). Mimoto does not GET `uri` itself.

## 2. Download flow

```text
Issuer
  sign mDoc MSO
  put status.status_list { uri, idx } in the MSO
  publish Token Status List CWT at uri
        |
        |  OpenID4VCI  (format = mso_mdoc, credential = base64url CBOR)
        v
Mimoto  CredentialServiceImpl.storeDownloadedCredential()
  processor.downloadCredential(...)
  CredentialVerifierServiceImpl.verify(response)
        |
        v
      CredentialsVerifier.verifyAndGetCredentialStatus(cred, format, purposes)
        // one call: crypto + status for any format
        // purposes from mosip.inji.credential.status.purpose-list
        |
        |  verificationStatus == false
        v
      VCVerificationException(library errorCode, message)   // do not store
        |
        |  verificationStatus == true
        v
      collectStatus(map):
          empty map            -> no pointer; persist empty (null on the row)
          purpose + error      -> credential_status_unavailable; do not store
          purpose + isValid    -> persist as-is (revoked/suspended still stored)
      isExpired:
          errorCode contains EXPIRED  -> true; still store
        |
        v
Inji Web
  200 + credentialId, statusChecks, lastCheckedAt, isExpired
  400 + credential_status_unavailable   (list could not be checked)
  400 + library crypto error            (including failed expiry)
```

Guest PDF uses the same `verify()`. It ignores status-unavailable and expiry and still generates the PDF. Signature / other crypto failure still fails.

## 3. What is in the credential

OpenID4VCI returns `format = mso_mdoc`. The credential field is a base64url CBOR IssuerSigned document. Status lives in the signed MSO, so `uri` and `idx` cannot be changed without breaking `issuerAuth`.

```text
{
  "docType": "org.iso.18013.5.1.mDL",
  "issuerSigned": {
    "nameSpaces": { ... },
    "issuerAuth":  COSE_Sign1 over the MSO     // tag 18
  }
}
```

MSO (text keys):

```text
{
  "validityInfo": { "validFrom": ..., "validUntil": ... },
  "status": {
    "status_list": {
      "idx": 42,
      "uri": "https://issuer.example/statuslists/1"
    }
  }
}
```

| MSO field | Use at download |
|---|---|
| `issuerAuth` | `vc-verifier` verifies this first. Then the MSO is trusted. |
| `validityInfo.validUntil` | If crypto still passes and the error code contains `EXPIRED`, store with `isExpired=true`. If crypto fails, throw and do not store. |
| `status.status_list.uri` | HTTPS URL the library GETs. |
| `status.status_list.idx` | Which entry to read after the CWT is validated. |

If the MSO has no `status` pointer, skip the GET. Empty map → no `statusChecks` on the row. `statusLastCheckedAt` is still set.

### Status list CWT (GET body)

```text
18( [ protected, unprotected, payload, signature ] )   // COSE_Sign1

protected:  { 1: alg, 16: "application/statuslist+cwt", 33: x5chain }
payload:    {
              2:     uri (must equal MSO uri),
              6:     iat,
              4:     exp,
              65534: ttl,
              65533: { "bits": 1 or 2, "lst": ZLIB+DEFLATE }
            }
```

| Value in `lst` at `idx` | Meaning |
|---|---|
| `0` | VALID |
| `1` | INVALID |
| `2` | SUSPENDED (`bits` = 2) |

## 4. vc-verifier contract

One call:

```text
credentialsVerifier.verifyAndGetCredentialStatus(credential, format, configured purposes)
```

Purposes always come from `mosip.inji.credential.status.purpose-list` (default `revocation,suspension`).

Returns `CredentialVerificationSummary`: `verificationResult` plus `Map<purpose, CredentialStatusResult>`.

### Status map (persist as-is)

| List value | `bits` | Map key | `isValid` | `error` |
|---|---|---|---|---|
| no `status` in MSO | — | *(empty map)* | — | — |
| `0` VALID | 1 | `"revocation"` | `true` | `null` |
| `0` VALID | 2 | `"revocation"` and `"suspension"` | `true` | `null` |
| `1` INVALID | 1 or 2 | `"revocation"` | `false` | `null` |
| `2` SUSPENDED | 2 | `"suspension"` | `false` | `null` |
| GET / CWT / idx / `bits` not 1 or 2 / unused value 3 | — | returned purposes | `false` | `StatusCheckException` |

`bits=1` VALID is only revocation. INVALID is only revocation. SUSPENDED is only suspension. A failed GET/CWT puts `error` on the purposes that were returned.

Never treat a failed fetch as VALID.

Library checks: COSE_Sign1 tag 18; `typ` 16; signature; `x5chain` 33; `sub` 2 equals MSO `uri`; `iat` 6; now ≤ `exp` 4; `status_list` 65533; `"bits"` 1 or 2; inflate `"lst"`; read bits at `idx` LSB first.

These APIs take the credential string and format. They do not depend on OpenID4VCI. The same call can be used later from OpenID4VP. This design only wires download and the stored-credential status API.

## 5. Mimoto changes

`CredentialServiceImpl` already calls `credentialVerifierService.verify()` before encrypt/store.

### `CredentialVerifierServiceImpl.verify(response)`

For **any format**:

1. `verifyAndGetCredentialStatus(credential, format, configured purposes)`.
2. If `verificationStatus == false` → `VCVerificationException` with the library code and message.
3. Copy the status map into `CredentialStatusCheck(purpose, valid)`. Any entry with `error != null` → `CredentialStatusException(CREDENTIAL_STATUS_UNAVAILABLE)`.
4. `isExpired` if `verificationErrorCode` contains `EXPIRED` (and crypto still passed).

### Wallet vs guest

| Path | Crypto fail | Status list error | Revoked / suspended | Expired (crypto still ok) |
|---|---|---|---|---|
| `storeDownloadedCredential` | throw; do not store | throw `credential_status_unavailable`; do not store | store `valid=false` | store `isExpired=true` |
| `generateCredentialPdf` | `signature_verification_failed` | ignore; still PDF | ignore; still PDF | ignore; still PDF |
| `checkCredentialStatus` | 400; leave stored status unchanged | 424; leave stored status unchanged | save `valid=false` | save `isExpired=true` |

Guest PDF uses the same configured purposes. It does not persist status.

### Persistence

On `verifiable_credentials`:

| Column | Content |
|---|---|
| `status_checks` | JSON list of `{purpose, valid}`. Empty map stored as null. |
| `status_last_checked_at` | Set on every successful verify (including empty map). |
| `is_expired` | From the verifier result. |

### APIs

`POST /wallets/{walletId}/credentials`

Response includes `statusChecks`, `lastCheckedAt`, `isExpired`.

`GET /wallets/{walletId}/credentials/{credentialId}/status`

Decrypts the stored VC, runs the same `verify()`, writes the new map. If verify throws, the previous row is left as-is.

OpenAPI: `docs/api-documentation-openapi.json`. Postman: Check Credential Status. Purposes come from `mosip.inji.credential.status.purpose-list`.

### Error codes

| Code | When | HTTP |
|---|---|---|
| `credential_status_unavailable` | GET / CWT / malformed / idx / unsupported `bits` on a returned purpose | download **400**; refresh **424** |
| library crypto code (e.g. `err_signature_verification_failed`, `err_vc_expired`) | `verificationStatus == false` | **400** |
| `signature_verification_failed` | guest PDF, crypto fail that is not expiry | existing PDF error |

No `credential_revoked` / `credential_suspended` / `credential_expired` download errors. Those states are data on the credential.

`CredentialStatusException` extends `VCVerificationException`.

`WalletCredentialsController`: `@ExceptionHandler(CredentialStatusException)` → 400 on download. The status method catches it itself and uses 424 when the code is `credential_status_unavailable`.

Guest PDF has no dedicated status handler; status exceptions are swallowed in `generateCredentialPdf`.

## 6. Download decision table

| Crypto | Status map | Store? | Result |
|---|---|---|---|
| fail (`verificationStatus` false) | ignored | No | `VCVerificationException` |
| pass | empty | Yes | `statusChecks` null |
| pass | `"revocation"` valid | Yes | `valid=true` |
| pass | `"revocation"` invalid | Yes | `valid=false` |
| pass | `"suspension"` invalid | Yes | `valid=false` |
| pass | purpose + `error` | No | `credential_status_unavailable` |
| pass + errorCode contains `EXPIRED` | as above | Yes | `isExpired=true` |

## 7. Inji Web

Inji Web does not fetch the list. It consumes the wallet APIs.

| Response | UI |
|---|---|
| 200 download / status + `statusChecks` | show per-purpose `valid`; revoked/suspended still on the card |
| 200 + `isExpired=true` | expired copy; credential is stored |
| `credential_status_unavailable` | retryable; distinct from signature failure (400 on download, 424 on refresh) |
| crypto `VCVerificationException` | existing signature / verifier copy; not stored |

## 8. Out of scope

- **Offline verification with cache.** Every check GETs a live CWT. Do not persist the list, reuse it by `ttl`, or check status when the wallet is offline.
- **OVP verification.** Presentation-time status is not wired here. When that work starts, reuse `verifyAndGetCredentialStatus`.

## 9. References

- [inji-wallet#2606](https://github.com/inji/inji-wallet/issues/2606)
- [IETF Token Status List draft 21](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html) — holder may fetch §1, §8; values §7.1; verify credential first §8.3
- [ISO/IEC 18013-5:2021](https://mosip.atlassian.net/wiki/spaces/Inji/pages/1547206743/Reference+Resources) — MSO / `issuerAuth`
- [ISO/IEC 18013-5 edition 2 / mdoc status lists](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/issues/84#:~:text=The%20first%20edition,List+for+mdocs.)
