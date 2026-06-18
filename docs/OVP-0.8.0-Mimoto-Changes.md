# OVP 0.8.0 — Mimoto Changes Reference

> This document covers **only what changes inside Mimoto** for the 0.7.0 → 0.8.0 migration.
> Each flow diagram shows: the old behaviour, the new behaviour, and the exact Mimoto file/method being changed.

## Flow 1 — Authorization Request Phase

**Triggered by:** `POST /wallets/{id}/presentations`

---

### 🔴 BEFORE (0.7.0)

```
POST /wallets/{id}/presentations
  Body: { authorizationRequestUrl: "openid4vp://..." }
         │
         ▼
📄 WalletPresentationServiceImpl.handleVPAuthorizationRequest()
  │
  ├─① verifierService.getTrustedVerifiers()  → List<Verifier>
  │
  ├─② OpenID4VPService.create(presentationId)
  │       └─ new OpenID4VP(id, new WalletMetadata())
  │               ↑ verifiers NOT passed here — lost after this point
  │
  └─③ openID4VP.authenticateVerifier(
            urlString,
            preRegisteredVerifiers,   ← passed as method arg (removed in 0.8.0)
            shouldValidate
        )
```

---

### 🟢 AFTER (0.8.0)

> **Library update:** `validatePreRegisteredVerifier` is now on `WalletConfig` (was `shouldValidateClient` on `authenticateVerifier`).

```
POST /wallets/{id}/presentations
  Body: { authorizationRequestUrl: "openid4vp://..." }
         │
         ▼
📄 WalletPresentationServiceImpl.handleVPAuthorizationRequest()
  │
  ├─① getPreRegisteredVerifiers()  → List<Verifier>
  │
  ├─② shouldValidateClient = isVerifierClientPreregistered(verifiers, url)
  │
  ├─③ OpenID4VPService.create(presentationId, trustedVerifiers, shouldValidateClient)
  │       └─ new WalletConfig(..., trustedVerifiers, validatePreRegisteredVerifier)
  │       └─ new OpenID4VP(id, walletConfig)
  │
  ├─④ openID4VP.authenticateVerifier(urlString)   ← 1 arg only
  │       └─ returns AuthorizationRequest subtype
  │
  ├─⑤ detect spec version
  │         if (authReq instanceof AuthorizationDcqlRequest)
  │               → specVersion = V1_0
  │         else
  │               → specVersion = DRAFT_23
  │
  └─⑥ store in session:
            presentationId, authorizationRequest, specVersion, isPreRegistered
            (isPreRegistered replayed as validatePreRegisteredVerifier on later create() calls)
```

---

### Changes in this flow

| # | What changes | Mimoto file | Type |
|---|-------------|-------------|------|
| 1 | `create()` takes `trustedVerifiers` + `validatePreRegisteredVerifier` | `OpenID4VPService.java` | Fix |
| 2 | `WalletConfig` replaces `WalletMetadata`; verifiers + validation flag inside it | `OpenID4VPService.java` | Fix |
| 3 | `authenticateVerifier(url)` — 1 arg only; no `shouldValidateClient` param | `WalletPresentationServiceImpl.java` | Fix |
| 4 | Spec version is detected from the `AuthorizationRequest` subtype | `WalletPresentationServiceImpl.java` | New |
| 5 | `specVersion` field stored in session | `VerifiablePresentationSessionData.java` | New |

> **Summary**
> This is the entry point of the entire VP flow. The wallet receives the verifier's authorization request URL, validates who the verifier is, and sets up the session for all subsequent calls.
> The key library moves for 0.8.0:
> - `trustedVerifiers` and `validatePreRegisteredVerifier` (formerly `shouldValidateClient`) now live in `WalletConfig` at `create()` time — compute `shouldValidateClient` from the URL **before** calling `create()`.
> - `authenticateVerifier()` is a 1-arg call; the library reads validation behaviour from `WalletConfig`.
> - 0.8.0 introduces two spec versions (Draft-23 and OVP 1.0 / DCQL). Mimoto detects which one the verifier is using by inspecting the returned `AuthorizationRequest` subtype (`AuthorizationDcqlRequest` → `V1_0`, anything else → `DRAFT_23`) and stores it as `specVersion` in the session. Every downstream call uses this value to pick the right code path. If `specVersion` is somehow absent (e.g. older session data), the fallback is `V1_0`.

---

## Flow 2 — Credential Matching Phase

**Triggered by:** `GET /wallets/{id}/presentations/{pid}/credentials`

---

### 🔴 BEFORE (0.7.0) — only one path existed

```
GET /wallets/{id}/presentations/{pid}/credentials
         │
         ▼
📄 CredentialMatchingServiceImpl.getMatchingCredentials()
  │
  ├─ openID4VPService.resolvePresentationDefinition(presentationId, authRequest, preReg)
  │       └─ called authenticateVerifier with 3 args (broken in 0.8.0)
  │       └─ cast to AuthorizationPresentationExchangeRequest
  │       └─ return presentationDefinition
  │
  ├─ walletCredentialService.getDecryptedCredentials(walletId, key)
  │
  ├─ for each InputDescriptor:
  │       match credentials by format + constraints/fields
  │       descriptorId NOT recorded — map key will be wrong at submission
  │
  └─ store matchingCredentials in session (WITHOUT descriptorId)
```

---

### 🟢 AFTER (0.8.0) — Draft-23 path

```
GET /wallets/{id}/presentations/{pid}/credentials
         │
         ▼
📄 CredentialMatchingServiceImpl.getMatchingCredentials()
  │
  ├─ session.specVersion == DRAFT_23  (explicit only — null defaults to V1_0)
  │
  ├─ openID4VPService.resolvePresentationDefinition(presentationId, authRequest, preReg)
  │       └─ create(..., preReg) → authenticateVerifier(url) — 1 arg
  │       └─ cast to AuthorizationPresentationExchangeRequest
  │       └─ return presentationDefinition
  │
  ├─ walletCredentialService.getDecryptedCredentials(walletId, key)
  │
  ├─ for each InputDescriptor:
  │       match credentials by format + constraints/fields
  │       record: credentialId → InputDescriptor.id  (stored as descriptorId)
  │
  ├─ build MatchingCredentialsResponseDTO:
  │       availableCredentials: List<CredentialDTO>  (flat, deduped)
  │       missingClaims: Set<String>
  │
  └─ store matchingCredentials WITH descriptorId per DTO in session
```

---

### 🟢 AFTER (0.8.0) — OVP 1.0 / DCQL path (entirely new)

```
GET /wallets/{id}/presentations/{pid}/credentials
         │
         ▼
📄 CredentialMatchingServiceImpl.getMatchingCredentials()
  │
  ├─ session.specVersion == V1_0
  │
  ├─ openID4VPService.resolveDcqlQuery(presentationId, authRequest, preReg)
  │       └─ create(id, verifiers, preReg) → authenticateVerifier(url)
  │       └─ cast to AuthorizationDcqlRequest
  │       └─ return dcqlQuery
  │
  ├─ walletCredentialService.getDecryptedCredentials(walletId, key)
  │
  ├─ for each CredentialQuery in dcqlQuery.credentials:
  │       queryId = credentialQuery.id
  │       format  = credentialQuery.format
  │       match wallet VCs by format
  │       if credentialQuery.claims != null → filter by claim paths/values
  │       if credentialQuery.multiple == false → allow only 1 match
  │       store dto.descriptorId = credentialQuery.id  (queryId as bridge key)
  │
  ├─ evaluate credentialSets (if present):
  │       for each CredentialSetQuery:
  │           if required=true and no option satisfied → mark missing
  │
  ├─ build DcqlMatchingCredentialsResponseDTO:
  │       queryGroups: List<DcqlQueryGroup>
  │           each: { queryId, multiple, availableCredentials, missingClaims }
  │       credentialSets: List<CredentialSetInfo>   ← option structure for the UI
  │           each: { required, options: List<List<queryId>> }
  │           e.g. { required:true, options:[["pan"],["aadhaar"],["voter_id","dl"]] }
  │       mandatory/optional logic lives only in credentialSets (not on queryGroup)
  │
  └─ store dcqlMatchingCredentials (with queryId as descriptorId) in session
```

---

### Changes in this flow

| # | What changes | Mimoto file | Type |
|---|-------------|-------------|------|
| 1 | `resolvePresentationDefinition()` passes `validatePreRegisteredVerifier` via `create()`; `authenticateVerifier` 1 arg | `OpenID4VPService.java` | Fix |
| 2 | `descriptorId` recorded on each matched DTO during Draft-23 matching | `CredentialMatchingServiceImpl.java` | Fix |
| 3 | Top-level routing by `specVersion` added | `CredentialMatchingServiceImpl.java` | New |
| 4 | `resolveDcqlQuery()` new method to extract `DCQLQuery` | `OpenID4VPService.java` | New |
| 5 | `matchDcql()` — full DCQL matching loop | `CredentialMatchingServiceImpl.java` | New |
| 6 | `matchesDcqlQuery()` — format + claim path matching helper | `CredentialMatchingServiceImpl.java` | New |
| 7 | `DcqlQueryGroup` DTO per query in response | `DcqlQueryGroup.java` | New |
| 8 | `descriptorId` field added to carry descriptor/queryId | `DecryptedCredentialDTO.java` | New |
| 9 | `queryGroups` + `isDcql` + `credentialSets` fields added to response | `MatchingCredentialsResponseDTO.java` | New |
| 10 | `CredentialSetInfo` DTO to carry option structure to the UI | `CredentialSetInfo.java` | New |

> **Summary**
> This flow finds which credentials in the wallet satisfy the verifier's request and presents them to the user for selection.
> Three things change here:
> - The `authenticateVerifier` 3-arg bug is fixed inside `resolvePresentationDefinition()`.
> - A critical missing piece is added for Draft-23: the `descriptorId` (i.e. which `InputDescriptor` each matched VC satisfies) is now recorded on each `DecryptedCredentialDTO` and stored in the session. Without this, the submission phase cannot build the correct map key that the library requires.
> - A completely new DCQL path is added. When `specVersion = V1_0`, Mimoto resolves a `DCQLQuery` instead of a `PresentationDefinition`, delegates all matching to `DCQLHelper.getMatchingCredentials()`, and builds a response with two layers: `queryGroups` (one per `CredentialQuery`) for individual slot details, and `credentialSets` (the option-grouping layer from the verifier's DCQL query) so the UI knows which queries are grouped into a section and what options the user can choose between. Both layers are needed — `queryGroups` alone is insufficient when `credential_sets` is present in the verifier request.

---

### 📦 API Response Body

> The response shape is **different** for Draft-23 and OVP 1.0. The `isDcql` flag tells the UI which shape to render.

---

#### When the VP request is NOT satisfiable

> **Rule:** Mimoto **never returns an HTTP error for an unsatisfiable request.**
> The `GET /credentials` endpoint always returns HTTP 200.
> Mimoto puts the mismatch information into the response body and lets the UI inform the user.
> The only action available to the user at that point is to reject via `PATCH` with `errorCode: access_denied`.

**Why Mimoto does not error here:**
The verifier has already sent a valid, well-formed authorization request. The wallet just happens to not have credentials that satisfy it. This is a business-level condition, not a protocol error. The protocol requires the wallet to either submit a VP or send `access_denied` back to the verifier — both happen through the existing `PATCH` endpoint.

---

##### Draft-23 — Unsatisfiable response shapes

**Case A — Wallet has no credentials at all**

```json
{
  "isDcql": false,
  "availableCredentials": [],
  "missingClaims": ["name", "dateOfBirth", "licenseNumber"]
}
```

**Case B — Wallet has credentials but none match any InputDescriptor**

```json
{
  "isDcql": false,
  "availableCredentials": [],
  "missingClaims": ["licenseNumber", "validUntil", "name", "dateOfBirth"]
}
```

**Case C — Wallet partially matches (some descriptors satisfied, some not)**

```json
{
  "isDcql": false,
  "availableCredentials": [
    { "credentialId": "vc-uuid-111", "credentialTypeDisplayName": "National ID Card", ... }
  ],
  "missingClaims": ["licenseNumber", "validUntil"]
}
```

> `missingClaims` comes from the `InputDescriptor`s that had zero matching credentials.
> If **any** descriptor is unsatisfied, `missingClaims` will be non-empty.
> If **all** descriptors are unsatisfied, `availableCredentials` will be empty.

**UI decision rule for Draft-23:**

| `availableCredentials` | `missingClaims` | What UI should do |
|------------------------|-----------------|-------------------|
| non-empty | empty | All requirements met — show credential picker, allow submit |
| non-empty | non-empty | Partial match — show available credentials + warn about missing ones |
| empty | non-empty | Fully unsatisfiable — show "missing credentials" screen, only allow reject |

---

##### OVP 1.0 / DCQL — Unsatisfiable response shapes

**Case A — Required query has no matching credential**

```json
{
  "isDcql": true,
  "queryGroups": [
    {
      "queryId": "pid_query",
      "multiple": false,
      "availableCredentials": [],
      "missingClaims": ["name", "dateOfBirth"]
    },
    {
      "queryId": "mdl_query",
      "multiple": false,
      "availableCredentials": [
        { "credentialId": "vc-uuid-222", "credentialTypeDisplayName": "Driving License", ... }
      ],
      "missingClaims": []
    }
  ],
  "credentialSets": []
}
```

> `pid_query` slot is unsatisfiable → UI shows that slot as "Not available".
> Since `credentialSets` is empty, all queryGroups are mandatory (DCQL default). `pid_query` has no match → user cannot submit — only reject.

**Case B — credentialSets present, at least one option is satisfiable**

Verifier accepts PAN OR Aadhaar OR (Voter ID + Driving License). Wallet only has Aadhaar:

```json
{
  "isDcql": true,
  "queryGroups": [
    { "queryId": "pan",      "availableCredentials": [], "missingClaims": ["pan","name"] },
    { "queryId": "aadhaar",  "availableCredentials": [{ "credentialId": "vc-aadh-222", ... }], "missingClaims": [] },
    { "queryId": "voter_id", "availableCredentials": [], "missingClaims": ["name"] },
    { "queryId": "dl",       "availableCredentials": [], "missingClaims": ["licenseNumber"] }
  ],
  "credentialSets": [
    {
      "required": true,
      "options": [["pan"], ["aadhaar"], ["voter_id", "dl"]]
    }
  ]
}
```

> Option `["aadhaar"]` is satisfiable → user can proceed by selecting Aadhaar.
> Options `["pan"]` and `["voter_id","dl"]` are not satisfiable → UI shows those tabs as unavailable.
> The section is still satisfiable overall.

**Case C — credentialSets present, NO option is satisfiable**

```json
{
  "isDcql": true,
  "queryGroups": [
    { "queryId": "pan",      "availableCredentials": [], "missingClaims": ["pan","name"] },
    { "queryId": "aadhaar",  "availableCredentials": [], "missingClaims": ["name","dob"] },
    { "queryId": "voter_id", "availableCredentials": [], "missingClaims": ["name"] },
    { "queryId": "dl",       "availableCredentials": [], "missingClaims": ["licenseNumber"] }
  ],
  "credentialSets": [
    {
      "required": true,
      "options": [["pan"], ["aadhaar"], ["voter_id", "dl"]]
    }
  ]
}
```

> Every option is unsatisfiable. The required section cannot be fulfilled → only reject.

**UI decision rule for DCQL:**

| Condition | What UI should do |
|-----------|-------------------|
| `credentialSets` empty — every queryGroup has `availableCredentials` non-empty | All requirements met — allow submit |
| `credentialSets` empty — any queryGroup has empty `availableCredentials` | Show those slots as "Not available" — disable submit, only allow reject |
| `credentialSets` present — at least one option has all its queries satisfied | Highlight satisfiable options — allow submit after user picks one option per required set |
| `credentialSets` present — no option has all its queries satisfied | Show section as "Cannot be satisfied" — only allow reject |

---

##### The reject flow when unsatisfiable

Regardless of whether the request is Draft-23 or DCQL, when the wallet cannot satisfy the request, the user rejects via the same endpoint:

```
PATCH /wallets/{id}/presentations/{pid}
Body:
{
  "errorCode": "access_denied",
  "errorMessage": "User does not have the required credentials"
}
```

Mimoto forwards this to the verifier via `openID4VP.sendErrorInfoToVerifier()`.
The verifier receives the `access_denied` error as required by the OpenID4VP spec.

#### Draft-23 Response — flat credential list

```json
{
  "isDcql": false,
  "availableCredentials": [
    {
      "credentialId": "vc-uuid-111",
      "credentialTypeDisplayName": "National ID Card",
      "credentialTypeLogo": "https://issuer.example.com/logo.png",
      "format": "ldp_vc",
      "claims":   ["$.name", "$.dateOfBirth", "$.address"],
      "sdClaims": ["$.email", "$.phoneNumber"]
    },
    {
      "credentialId": "vc-uuid-222",
      "credentialTypeDisplayName": "Driving License",
      "credentialTypeLogo": "https://issuer.example.com/dl-logo.png",
      "format": "ldp_vc",
      "claims":   ["$.licenseNumber", "$.validUntil"],
      "sdClaims": []
    }
  ],
  "missingClaims": ["age_over_18"]
}
```

| Field | Meaning |
|-------|---------|
| `availableCredentials` | VCs in the wallet that satisfy the verifier's `PresentationDefinition` — flat, de-duplicated |
| `credentialId` | VC UUID — what the user sends back in the submit request |
| `credentialTypeDisplayName` | Human-readable name shown in the UI |
| `credentialTypeLogo` | Logo URL for the credential card |
| `format` | Credential format (`ldp_vc`, `vc+sd-jwt`, etc.) |
| `claims` | Claims that are **always disclosed** — shown pre-selected in UI |
| `sdClaims` | **Selective Disclosure** claims — user must consent to share |
| `missingClaims` | Claims the verifier needs but **no wallet credential has** — shown as "missing" in UI |

---

#### DCQL two-layer structure — understand this first

DCQL responses have **two layers**. Understanding this distinction is essential for correct UI rendering.

```
DCQLQuery
├── credentials: List<CredentialQuery>     ← Layer 1: individual credential slots
│       each: { id, format, multiple, claims }
│       id is what the UI sends back in selectedCredentials (as object element)
│
└── credential_sets: List<CredentialSetQuery>?   ← Layer 2: section / option grouping
        each: {
          required: Boolean        ← is this section mandatory?
          options: [               ← OR between options — user picks exactly ONE
            ["query_a"],           ←   Option 1: only query_a needed
            ["query_b"],           ←   Option 2: only query_b needed
            ["query_c","query_d"]  ←   Option 3: query_c AND query_d needed together
          ]
        }
```

- When `credential_sets` is **absent** → every `CredentialQuery` is an independent mandatory slot (DCQL default). UI infers this from `credentialSets: []` — no per-query `required` field is sent.
- When `credential_sets` is **present** → mandatory/optional logic lives in `credentialSets[].required` and `credentialSets[].options`. Queries inside a set are only required when the user picks the option that contains them.

#### OVP 1.0 / DCQL Response — example without credential_sets

The simplest case: two independent required slots (e.g. national ID + driving license, both always needed).

```json
{
  "isDcql": true,
  "queryGroups": [
    {
      "queryId": "pid_query",
      "multiple": false,
      "availableCredentials": [
        {
          "credentialId": "vc-uuid-111",
          "credentialTypeDisplayName": "National ID Card",
          "format": "ldp_vc",
          "claims":   ["$.name", "$.dateOfBirth"],
          "sdClaims": ["$.email"]
        }
      ],
      "missingClaims": []
    },
    {
      "queryId": "mdl_query",
      "multiple": false,
      "availableCredentials": [
        {
          "credentialId": "vc-uuid-222",
          "credentialTypeDisplayName": "Driving License",
          "format": "ldp_vc",
          "claims":   ["$.licenseNumber"],
          "sdClaims": []
        }
      ],
      "missingClaims": []
    }
  ],
  "credentialSets": []
}
```

> `credentialSets` is empty → both slots are mandatory. UI does not need a `required` flag on each `queryGroup`.

#### OVP 1.0 / DCQL Response — example with credential_sets (options)

A more complex case: the verifier accepts **PAN card OR Aadhaar OR (Voter ID + Driving License)** as proof of identity. The user must satisfy exactly one option from this section.

```json
{
  "isDcql": true,
  "queryGroups": [
    {
      "queryId": "pan",
      "multiple": false,
      "availableCredentials": [
        { "credentialId": "vc-pan-111", "credentialTypeDisplayName": "PAN Card", "format": "ldp_vc", "claims": ["$.name","$.pan"], "sdClaims": [] }
      ],
      "missingClaims": []
    },
    {
      "queryId": "aadhaar",
      "multiple": false,
      "availableCredentials": [
        { "credentialId": "vc-aadh-222", "credentialTypeDisplayName": "Aadhaar Card", "format": "ldp_vc", "claims": ["$.name","$.dob"], "sdClaims": ["$.address"] }
      ],
      "missingClaims": []
    },
    {
      "queryId": "voter_id",
      "multiple": false,
      "availableCredentials": [
        { "credentialId": "vc-vid-333", "credentialTypeDisplayName": "Voter ID", "format": "ldp_vc", "claims": ["$.name"], "sdClaims": [] }
      ],
      "missingClaims": []
    },
    {
      "queryId": "dl",
      "multiple": false,
      "availableCredentials": [
        { "credentialId": "vc-dl-444", "credentialTypeDisplayName": "Driving License", "format": "ldp_vc", "claims": ["$.licenseNumber"], "sdClaims": [] }
      ],
      "missingClaims": []
    }
  ],
  "credentialSets": [
    {
      "required": true,
      "options": [
        ["pan"],
        ["aadhaar"],
        ["voter_id", "dl"]
      ]
    }
  ]
}
```

> **Mandatory logic is on `credentialSets`, not on `queryGroup`:** the section (`credentialSets[0].required = true`) is what's mandatory. Each query is only required if the user picks the option that contains it. `queryGroups` carry slot details only — no `required` field.

| Field | Meaning |
|-------|---------|
| `queryGroups` | One entry per `CredentialQuery` — describes the credential type, available VCs, and missing claims for each slot |
| `queryId` | The `CredentialQuery.id` — must be sent back in the submit request |
| `multiple` | `true` → user may pick more than one credential for this slot · `false` → exactly one |
| `availableCredentials` | VCs in the wallet that match this query slot |
| `missingClaims` | Claims this query needs but no wallet VC satisfies |
| `credentialSets` | The option-grouping layer. Each entry is one **section** in the UI |
| `credentialSets[].required` | `true` → user must satisfy one option in this section · `false` → section is optional |
| `credentialSets[].options` | List of options. User picks **exactly one**. Each option is a list of queryIds that must **all** be presented together (AND within option, OR between options) |

#### How the UI decides what to render

```
isDcql == false
  → render flat credential list from availableCredentials
  → user picks any credential(s)
  → submit: { "selectedCredentials": ["vc-uuid-111"] }


isDcql == true  AND  credentialSets is empty
  → render one card/slot per queryGroup
  → all slots are mandatory (DCQL default when credential_sets is absent)
  → queryGroup.multiple == true  → allow multi-select within the slot
  → submit only when every queryGroup has a selected credential
  → submit: { "selectedCredentials": [{ "queryId": "pid_query", "selectedCredentialIds": ["vc-uuid-111"] }] }


isDcql == true  AND  credentialSets is non-empty
  → render one SECTION per credentialSet entry
  → credentialSet.required == true  → section header shows "Required"
  → credentialSet.required == false → section header shows "Optional"
  → within each section, render one TAB / RADIO OPTION per option entry:
        option = ["pan"]             → tab shows the PAN card slot
        option = ["aadhaar"]         → tab shows the Aadhaar slot
        option = ["voter_id", "dl"]  → tab shows BOTH Voter ID + Driving License slots (user must fill both)
  → user selects one tab per required section
  → queryGroups NOT in any credentialSet render as independent mandatory slots outside sections
  → submit: {
        "selectedCredentials": [
          { "queryId": "voter_id", "selectedCredentialIds": ["vc-vid-333"] },
          { "queryId": "dl",       "selectedCredentialIds": ["vc-dl-444"] }
        ]
      }
```

---

## Flow 3 — Presentation Submission Phase

**Triggered by:** `PATCH /wallets/{id}/presentations/{pid}`

---

### 🔴 BEFORE (0.7.0) — only Draft-23, wrong map key

```
PATCH /wallets/{id}/presentations/{pid}
  Body: { selectedCredentials: ["vc-id-1", "vc-id-2"] }
         │
         ▼
📄 WalletPresentationServiceImpl.submitPresentation()
  │
  ├─① fetchSelectedCredentials(sessionData, selectedIds)
  │
  ├─② create(presentationId, verifiers, isPreReg) + authenticateVerifier(url)
  │                                                        ↑ 3 args — broken in 0.8.0
  │
  ├─③ convertCredentialsToJarFormat()
  │       groups by dto.getId()  ← BUG: VC's own UUID, not the descriptor id
  │       output: Map<vc-uuid, List<Credential>>   ← WRONG KEY
  │
  ├─④ openID4VP.constructUnsignedVPToken(wrongMap)
  │       library looks up "id_card_descriptor" → finds nothing → VP broken
  │
  ├─⑤ signVPToken(unsignedVPTokens, jwsSigner)
  │
  └─⑥ openID4VP.sendVPResponseToVerifier(signingResults)
```

---

### 🟢 AFTER (0.8.0) — Draft-23 path

```
PATCH /wallets/{id}/presentations/{pid}
  Body: { selectedCredentials: ["vc-id-1", "vc-id-2"] }
         │
         ▼
📄 WalletPresentationServiceImpl.submitPresentation()
  │
  ├─① fetchSelectedCredentials(sessionData, selectedIds)
  │       └─ filters session.matchingCredentials by selectedIds
  │       └─ each DecryptedCredentialDTO has .descriptorId set from matching step
  │
  ├─② create(presentationId, verifiers)
  │   create(..., isPreReg) → authenticateVerifier(authRequest)   ← 1 arg (fixed)
  │
  ├─③ buildDescriptorCredentialMap(selectedCredentials)
  │       input:  List<DecryptedCredentialDTO>
  │       output: Map<descriptorId, List<Credential>>   ← correct key
  │           e.g. { "id_card_descriptor": [Credential(LDP_VC, vcData, "vc-id-1")] }
  │
  ├─④ openID4VP.constructUnsignedVPToken(descriptorCredentialMap)
  │       returns List<UnsignedVPToken>
  │           each: { format=LDP_VC, signatureAlgorithm="EdDSA", dataToSign=<bytes> }
  │
  ├─⑤ signVPToken(unsignedVPTokens, keyPair, signingAlgorithm)
  │       for each UnsignedVPToken:
  │           signer = SigningKeyUtil.createSigner(algo, jwk)
  │           signature = signer.sign(JWSHeader(algo), dataToSign).decode()
  │           → VPTokenSigningResult(signedData = rawBytes)
  │       returns List<VPTokenSigningResult>
  │
  └─⑥ openID4VP.sendVPResponseToVerifier(List<VPTokenSigningResult>)
           returns VerifierResponse
```

---

### 🟢 AFTER (0.8.0) — OVP 1.0 / DCQL path (entirely new)

```
PATCH /wallets/{id}/presentations/{pid}
  Body: {
    selectedCredentials: [
      { queryId: "pid_query",  selectedCredentialIds: ["vc-id-1"] },
      { queryId: "mdl_query",  selectedCredentialIds: ["vc-id-2"] }
    ]
  }
         │
         ▼
📄 WalletPresentationServiceImpl.submitPresentation()
  │
  ├─① validateDcqlSelections(request, sessionData)
  │       enforce mandatory credential_sets must be satisfied
  │       enforce multiple=false → max 1 credential per query
  │
  ├─② buildQueryCredentialMap(request.getDcqlSelections(), sessionData)
  │       for each DcqlCredentialSelection:
  │           resolve credentials by selectedCredentialIds from session cache
  │           key = selection.queryId
  │       output: Map<queryId, List<Credential>>
  │           e.g. { "pid_query": [Credential(...)], "mdl_query": [Credential(...)] }
  │
  ├─③ create(presentationId, verifiers)
  │   create(..., isPreReg) → authenticateVerifier(authRequest)
  │
  ├─④ openID4VP.constructUnsignedVPToken(queryCredentialMap)
  │       same library call as Draft-23
  │       library handles both spec versions internally
  │       returns List<UnsignedVPToken>
  │
  ├─⑤ signVPToken(unsignedVPTokens, keyPair, signingAlgorithm)
  │       identical signing loop to Draft-23
  │
  └─⑥ openID4VP.sendVPResponseToVerifier(List<VPTokenSigningResult>)
           returns VerifierResponse
```

---

### Changes in this flow

| # | What changes | Mimoto file | Type |
|---|-------------|-------------|------|
| 1 | `create(..., isPreReg)` + `authenticateVerifier` 1 arg | `WalletPresentationServiceImpl.java` | Fix |
| 2 | `convertCredentialsToJarFormat()` replaced by `buildDescriptorCredentialMap()` — map key changed from `dto.getId()` to `dto.getDescriptorId()` | `WalletPresentationServiceImpl.java` | Fix |
| 3 | Submission branches by `request.isDcqlSubmission()` | `WalletPresentationServiceImpl.java` | New |
| 4 | `validateDcqlSelections()` enforces DCQL constraints | `WalletPresentationServiceImpl.java` | New |
| 5 | `buildQueryCredentialMap()` builds `Map<queryId, Credential>` for DCQL | `WalletPresentationServiceImpl.java` | New |
| 6 | `selectedCredentials` now accepts array-of-strings (Draft-23) or array-of-objects (DCQL) | `SubmitPresentationRequestDTO.java` | Fix |
| 7 | `DcqlCredentialSelection` DTO (queryId + selectedCredentialIds) | `DcqlCredentialSelection.java` | New |

> **Summary**
> This is the final step — the user has chosen which credentials to share and Mimoto packs them into a signed VP and sends it to the verifier.
> Three things change here:
> - The `authenticateVerifier` 3-arg bug is fixed (same issue as in Flows 1 and 4).
> - The most important bug fix: `convertCredentialsToJarFormat()` was building the map with the VC's own UUID as the key (`dto.getId()`). The library expects the `InputDescriptor.id` (or DCQL `queryId`) as the key. The replacement method `buildDescriptorCredentialMap()` reads `dto.getDescriptorId()` — the value that was stored during the matching phase — and uses it as the correct map key. Without this fix the library cannot match credentials to descriptor slots and the VP is invalid.
> - A new DCQL submission path is added. The `selectedCredentials` field is polymorphic: when elements are plain strings Mimoto treats it as Draft-23; when elements are objects with `queryId` + `selectedCredentialIds` Mimoto treats it as DCQL. Before building the map, `validateDcqlSelections()` enforces DCQL constraints (`multiple=false` and mandatory `credentialSets`). The map is then built with `queryId` as the key. From step ④ onwards (construct → sign → send) the code is identical to the Draft-23 path — the library handles both spec versions internally.

---

### 📦 API Request & Response Body

> The **request body** differs between Draft-23 and DCQL. The **response body** is the same shape for both.

#### Request — Draft-23 (submit selected credentials)

`selectedCredentials` is an **array of strings** — the credential IDs the user chose.

```json
{
  "selectedCredentials": ["vc-uuid-111", "vc-uuid-222"]
}
```

#### Request — OVP 1.0 / DCQL (submit with query mapping)

`selectedCredentials` is an **array of objects** — each object maps a DCQL query slot to the credential(s) the user chose for it.

```json
{
  "selectedCredentials": [
    { "queryId": "pid_query", "selectedCredentialIds": ["vc-uuid-111"] },
    { "queryId": "mdl_query", "selectedCredentialIds": ["vc-uuid-222"] }
  ]
}
```

> **How Mimoto detects which path to take:** if the first element of `selectedCredentials` is a plain string → Draft-23 path. If it is an object with `queryId` → DCQL path. Both cases use the same field name.

#### Request — Rejection (user declines)

```json
{
  "errorCode": "access_denied",
  "errorMessage": "User denied authorization to share credentials"
}
```

---

#### Response — Submission success (HTTP 200)

```json
{
  "status": "SUCCESS",
  "message": "Presentation successfully submitted and shared with verifier",
  "redirectUri": "https://verifier.example.com/callback?state=af0ifjsldkj"
}
```

#### Response — Submission failed (HTTP 200)

```json
{
  "status": "ERROR",
  "message": "Failed to share verifiable presentation with verifier",
  "redirectUri": null
}
```

#### Response — Rejection sent (HTTP 200)

```json
{
  "status": "REJECTED_VERIFIER",
  "message": "Verifier has been notified of the rejection",
  "redirectUri": "https://verifier.example.com/error?error=access_denied"
}
```

| Field | Meaning |
|-------|---------|
| `status` | `SUCCESS` — VP accepted by verifier · `ERROR` — VP send failed · `REJECTED_VERIFIER` — user declined |
| `message` | Human-readable result for the UI |
| `redirectUri` | URL to redirect the user back to the verifier's app. `null` if verifier did not respond |

#### Important — Mimoto is NOT the final destination

The signed VP token travels **Mimoto → Verifier** directly inside `sendVPResponseToVerifier()`. The wallet app never sees the VP token itself. The `redirectUri` in the response tells the wallet app where to send the user next.

```
Wallet App           Mimoto                  Verifier
    │                   │                       │
    ├── PATCH /submit ──►│                       │
    │  {selectedCreds}   ├──── signed VP ────────►│
    │                    │◄─── HTTP 200 ──────────┤
    │◄── {status,        │                       │
    │     redirectUri} ──┤                       │
```

---

## Flow 4 — Error / Rejection Path

**Triggered by:** `PATCH /wallets/{id}/presentations/{pid}` with `errorCode` + `errorMessage`

---

### 🔴 BEFORE (0.7.0)

```
📄 OpenID4VPService.sendErrorToVerifier()
  │
  └─ openID4VP.authenticateVerifier(
         authRequest,
         preRegisteredVerifiers,   ← 3 args — broken in 0.8.0
         isVerifierClientPreregistered
     )
```

---

### 🟢 AFTER (0.8.0)

```
PATCH /wallets/{id}/presentations/{pid}
  Body: { errorCode: "access_denied", errorMessage: "User denied" }
         │
         ▼
📄 WalletPresentationServiceImpl.rejectVerifier()
  │
  └─ openID4VPService.sendErrorToVerifier(sessionData, errorPayload)
          │
          ├─ create(presentationId, preRegisteredVerifiers, isPreReg)
          ├─ authenticateVerifier(authRequest)  ← 1 arg (fixed)
          ├─ map errorCode → OpenID4VPException
          │       access_denied           → AccessDenied
          │       invalid_transaction_data → InvalidTransactionData
          │       anything else           → AccessDenied (default)
          └─ openID4VP.sendErrorInfoToVerifier(OpenID4VPException)
```

---

### Changes in this flow

| # | What changes | Mimoto file | Type |
|---|-------------|-------------|------|
| 1 | `create(..., validatePreRegisteredVerifier)` + `authenticateVerifier` 1 arg | `OpenID4VPService.java` | Fix |

> **Summary**
> This flow handles the case where the user declines to share credentials and the wallet must notify the verifier.
> The change here is the same as other flows: pass `validatePreRegisteredVerifier` via `create()`, then call `authenticateVerifier(authRequest)` with 1 arg. The reason `authenticateVerifier` must be called at all on the rejection path is that the `OpenID4VP` library object is stateless between HTTP calls — it must re-authenticate the verifier to populate its internal state before it can send anything, including an error. Without this re-authentication call the library does not know where to send the error response.

---

## All Mimoto Files Changed — Summary

### Modified files

| File | What changes |
|------|-------------|
| `pom.xml` | Library version `0.7.0-SNAPSHOT-myLocal` → `0.8.0-myLocal` |
| `OpenID4VPService.java` | `WalletConfig` replaces `WalletMetadata` · `validatePreRegisteredVerifier` in config · `authenticateVerifier` 1-arg · new `resolveDcqlQuery()` method |
| `WalletPresentationServiceImpl.java` | `create(..., isPreReg)` + `authenticateVerifier` 1-arg · `buildDescriptorCredentialMap()` replaces `convertCredentialsToJarFormat()` · DCQL submission branch · `validateDcqlSelections()` · `buildQueryCredentialMap()` |
| `CredentialMatchingServiceImpl.java` | `specVersion` routing · `descriptorId` recording in Draft-23 matching · new `matchDcql()` branch · `matchesDcqlQuery()` helper |
| `VerifiablePresentationSessionData.java` | Add `specVersion` field (`DRAFT_23` or `V1_0`); default when null is `V1_0` |
| `DecryptedCredentialDTO.java` | Add `descriptorId` field (bridge key from matching → submission) |
| `SubmitPresentationRequestDTO.java` | `selectedCredentials` becomes polymorphic: `List<String>` (Draft-23) or `List<DcqlCredentialSelection>` (DCQL) · update `isSubmissionRequest()`, `isRejectionRequest()`, and add `isDcqlSubmission()` helper |
| `MatchingCredentialsResponseDTO.java` | Add `queryGroups` field · add `isDcql` flag |

### New files

| File | Purpose |
|------|---------|
| `SpecVersion.java` | Enum: `DRAFT_23` \| `V1_0` |
| `DcqlQueryGroup.java` | DTO: one query's matching result (queryId, multiple, availableCredentials, missingClaims) |
| `DcqlCredentialSelection.java` | DTO: one user selection for a DCQL query (queryId + selectedCredentialIds) |

### Test files updated

| File | What changes |
|------|-------------|
| `OpenID4VPServiceTest.java` | `create()` takes `validatePreRegisteredVerifier` · `authenticateVerifier` mocked as 1-arg |
| `WalletPresentationServiceTest.java` | Update mocks · add DCQL submission test · add constraint validation test |
| `CredentialMatchingServiceTest.java` | Add explicit `specVersion = DRAFT_23` to Draft-23 test setups (null now defaults to V1_0) · add DCQL matching tests |
