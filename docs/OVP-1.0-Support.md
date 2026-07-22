# OpenID4VP 1.0 support in Inji Web Wallet

This document describes how **Inji Web Wallet clients and integrators** should use Mimoto’s presentation APIs when the verifier sends an **OpenID4VP 1.0 (DCQL)** authorization request.

It focuses on **API contracts, response shapes, and UI behaviour** — not internal implementation details.

For the older **Presentation Exchange (Draft-23)** flow, see [Appendix A](#appendix-a-draft-23-presentation-exchange).

---

## Overview

OVP 1.0 uses **DCQL** (Digital Credentials Query Language) instead of a flat `presentation_definition`. Mimoto exposes three session-authenticated endpoints under:

```text
/wallets/{walletId}/presentations
```

| Step | Method | Path | Purpose |
|------|--------|------|---------|
| 1 | `POST` | `/wallets/{walletId}/presentations` | Parse verifier authorization request, create presentation session |
| 2 | `GET` | `/wallets/{walletId}/presentations/{presentationId}/credentials` | List wallet credentials that match the verifier’s DCQL query |
| 3 | `PATCH` | `/wallets/{walletId}/presentations/{presentationId}` | Submit selected credentials to the verifier, or reject the request |

**Prerequisites**

- Valid Mimoto **session** (user authenticated).
- Wallet **unlock key** present in session (`WALLET_KEY`) before steps 2 and 3.
- For state-changing calls (`PATCH`), include the **CSRF** token (`X-XSRF-TOKEN` header).

**Important:** Always call **GET /credentials** before **PATCH** submit. Submit uses credential IDs cached in the presentation session from that GET response. Unknown IDs are rejected.

---

## Detecting OVP 1.0 vs Draft-23

Mimoto selects the matching and submission path from the verifier authorization request:

| Verifier request type | Mimoto behaviour |
|----------------------|------------------|
| DCQL (`AuthorizationDcqlRequest`) | **OVP 1.0** — use `queryGroups` / `credentialSets` |
| Presentation Exchange | **Draft-23** — use flat `availableCredentials` |

**How the wallet UI knows which response shape to expect**

| GET /credentials response | Meaning |
|---------------------------|---------|
| `queryGroups` is present | OVP 1.0 / DCQL |
| `availableCredentials` is present (no `queryGroups`) | Draft-23 |

Do not send a mixed `selectedCredentials` array on submit — elements must be **all strings** (Draft-23) or **all objects** (DCQL).

---

## Step 1 — Start presentation (`POST`)

**Request**

```json
{
  "authorizationRequestUrl": "openid4vp://authorize?client_id=..."
}
```

**Response (200)**

```json
{
  "presentationId": "presentation-uuid",
  "verifier": {
    "clientId": "verifier-client-id",
    "clientName": "Example Verifier",
    "logoUri": "https://verifier.example.com/logo.png",
    "trusted": true,
    "preregisteredWithWallet": true
  }
}
```

Store `presentationId` for the remaining steps.

---

## Step 2 — Get matching credentials (`GET`)

```http
GET /wallets/{walletId}/presentations/{presentationId}/credentials
```

### DCQL response model

A DCQL response has **two layers**:

```text
DCQL query (from verifier)
├── credentials[]          ← Layer 1: one slot per CredentialQuery (→ queryGroups)
└── credential_sets[]?     ← Layer 2: optional OR-grouping
                             → always returned as credentialSets (synthesised if omitted)
```

- **`queryGroups`** — one entry per `CredentialQuery.id`. Describes available credentials, formats, claims, and missing claims for that slot.
- **`credentialSets`** — option-grouping layer for the UI. When the verifier sends `credential_sets`, those options are returned as-is. When the verifier **omits** `credential_sets`, Mimoto synthesises one **required** set per `queryGroups` entry (single option containing that `queryId`), so the client always renders from `credentialSets` the same way.

### Example — two independent required queries

Verifier needs national ID **and** driving license (no `credential_sets`). The response still includes synthesised `credentialSets` — one mandatory section per query:

```json
{
  "queryGroups": [
    {
      "queryId": "pid_query",
      "multiple": false,
      "availableCredentials": [
        {
          "credentialId": "vc-uuid-111",
          "credentialTypeDisplayName": "National ID Card",
          "credentialTypeLogo": "https://issuer.example.com/logo.png",
          "format": "ldp_vc",
          "claims": ["$.name", "$.dateOfBirth"],
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
          "claims": ["$.licenseNumber"],
          "sdClaims": []
        }
      ],
      "missingClaims": []
    }
  ],
  "credentialSets": [
    {
      "required": true,
      "options": [["pid_query"]]
    },
    {
      "required": true,
      "options": [["mdl_query"]]
    }
  ]
}
```

### Example — `credential_sets` with options

Verifier accepts **PAN OR Aadhaar OR (Voter ID + Driving License)**:

```json
{
  "queryGroups": [
    {
      "queryId": "pan",
      "multiple": false,
      "availableCredentials": [
        {
          "credentialId": "vc-pan-111",
          "credentialTypeDisplayName": "PAN Card",
          "format": "ldp_vc",
          "claims": ["$.name", "$.pan"],
          "sdClaims": []
        }
      ],
      "missingClaims": []
    },
    {
      "queryId": "aadhaar",
      "multiple": false,
      "availableCredentials": [
        {
          "credentialId": "vc-aadh-222",
          "credentialTypeDisplayName": "Aadhaar Card",
          "format": "ldp_vc",
          "claims": ["$.name", "$.dob"],
          "sdClaims": ["$.address"]
        }
      ],
      "missingClaims": []
    },
    {
      "queryId": "voter_id",
      "multiple": false,
      "availableCredentials": [
        {
          "credentialId": "vc-vid-333",
          "credentialTypeDisplayName": "Voter ID",
          "format": "ldp_vc",
          "claims": ["$.name"],
          "sdClaims": []
        }
      ],
      "missingClaims": []
    },
    {
      "queryId": "dl",
      "multiple": false,
      "availableCredentials": [
        {
          "credentialId": "vc-dl-444",
          "credentialTypeDisplayName": "Driving License",
          "format": "ldp_vc",
          "claims": ["$.licenseNumber"],
          "sdClaims": []
        }
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

### Field reference

| Field | Description |
|-------|-------------|
| `queryGroups[].queryId` | `CredentialQuery.id` — **must** be sent back on submit |
| `queryGroups[].multiple` | `true` → user may select more than one credential for this query; `false` → at most one |
| `queryGroups[].availableCredentials` | Wallet credentials that satisfy this query |
| `queryGroups[].missingClaims` | JSON paths the query requires but no wallet credential satisfies |
| `credentialSets[].required` | `true` → user must satisfy **one** option in this section |
| `credentialSets[].options` | Each option is a list of `queryId`s that must **all** be submitted together (AND within option, OR between options) |
| `availableCredentials[].credentialId` | Wallet credential UUID — use in submit `selectedCredentialIds` |
| `availableCredentials[].claims` | Always-disclosed claim paths (shown pre-selected in UI) |
| `availableCredentials[].sdClaims` | Selectively disclosable paths — user must opt in (SD-JWT only) |

### UI rendering guide

```text
Always render from credentialSets (never treat an empty list as the omit-default)
  → One section per credentialSet entry
  → required=true → section is mandatory
  → Within a section, render one option (tab/radio) per options[] entry
  → Option ["voter_id","dl"] → user must fill BOTH slots in that option
  → User picks exactly one option per required section
  → Look up slot details (credentials, claims, multiple) in queryGroups by queryId
  → Synthesised sets (verifier omitted credential_sets) look like
    [{ required: true, options: [["pid_query"]] }, { required: true, options: [["mdl_query"]] }]
    → same UI path: one mandatory section per query, one option each
```

### Unsatisfiable requests

If no credential matches a required query, `availableCredentials` is empty and `missingClaims` lists what is missing. The wallet may still let the user **reject** the verifier (see Step 3).

---

## Step 3 — Submit or reject (`PATCH`)

```http
PATCH /wallets/{walletId}/presentations/{presentationId}
```

### Submit — DCQL (`selectedCredentials` as objects)

```json
{
  "selectedCredentials": [
    {
      "queryId": "pid_query",
      "selectedCredentialIds": ["vc-uuid-111"]
    },
    {
      "queryId": "mdl_query",
      "selectedCredentialIds": ["vc-uuid-222"]
    }
  ]
}
```

**Rules enforced by Mimoto**

- Every `selectedCredentialIds` entry must exist in the session cache from GET /credentials.
- `queryId` must match a credential query in the verifier’s DCQL request.
- When `multiple` is `false` for a query, at most **one** credential may be selected for that `queryId` (duplicate selections for the same query are merged and counted).
- When `credential_sets` has a **required** section, the selected `queryId`s must match **exactly one** option in that section.

### Same credential across multiple queries

One wallet credential may satisfy several DCQL queries. Submit one selection object per query, repeating the same `credentialId` where needed:

```json
{
  "selectedCredentials": [
    {
      "queryId": "age-proof",
      "selectedCredentialIds": ["a3e92fcf-b107-46c9-8d68-f10cdbe8214b"]
    },
    {
      "queryId": "government-identity",
      "selectedCredentialIds": ["a3e92fcf-b107-46c9-8d68-f10cdbe8214b"]
    }
  ]
}
```

### SD-JWT selective disclosure (`selectedSdClaims`)

For `vc+sd-jwt` and `dc+sd-jwt` credentials, `selectedSdClaims` is a map of **credential ID → array of claim paths**:

```json
{
  "selectedCredentials": [
    {
      "queryId": "age-proof",
      "selectedCredentialIds": ["a3e92fcf-b107-46c9-8d68-f10cdbe8214b"],
      "selectedSdClaims": {
        "a3e92fcf-b107-46c9-8d68-f10cdbe8214b": ["dateOfBirth"]
      }
    },
    {
      "queryId": "government-identity",
      "selectedCredentialIds": ["a3e92fcf-b107-46c9-8d68-f10cdbe8214b"],
      "selectedSdClaims": {
        "a3e92fcf-b107-46c9-8d68-f10cdbe8214b": ["region"]
      }
    }
  ]
}
```

**SD-JWT behaviour**

| Situation | What is shared |
|-----------|----------------|
| `selectedSdClaims` lists paths for a credential | Only those selectively disclosable claims |
| `selectedSdClaims` omitted or empty for an SD-JWT credential | **No** SD disclosures (credential JWT only) |
| Paths from multiple queries for the same credential | **Union** of all paths (deduplicated) |

Paths may be sent as `dateOfBirth`, `$.dateOfBirth`, or `credentialSubject.dateOfBirth` — Mimoto normalizes them to match stored SD claim keys.

You may also place `selectedSdClaims` at the **top level** of the submit body; Mimoto unions top-level and per-selection maps.

### `claim_sets` and auto-resolved disclosures

When the verifier’s DCQL query defines `claim_sets` on a credential query and the client does **not** send explicit `selectedSdClaims` for that credential, Mimoto may auto-resolve the first satisfiable claim set and include the corresponding SD-JWT paths on submit.

When the user **does** send `selectedSdClaims`, those explicit paths take precedence for that credential/query combination.

### Reject verifier

```json
{
  "errorCode": "access_denied",
  "errorMessage": "User denied authorization to share credentials"
}
```

Do not include `selectedCredentials` or `selectedSdClaims` in a rejection request.

### Submit / reject responses (HTTP 200)

**Success**

```json
{
  "status": "SUCCESS",
  "message": "Presentation successfully submitted and shared with verifier",
  "redirectUri": "https://verifier.example.com/callback?state=..."
}
```

**Share failed**

```json
{
  "status": "ERROR",
  "message": "Failed to share verifiable presentation with verifier",
  "redirectUri": null
}
```

**Rejection sent**

```json
{
  "status": "REJECTED_VERIFIER",
  "message": "Verifier has been notified of the rejection",
  "redirectUri": "https://verifier.example.com/error?error=access_denied"
}
```

`redirectUri` is the verifier’s callback URL. The wallet should redirect the user there when present. Mimoto is not the browser’s final destination after a successful share.

---

## End-to-end flow (OVP 1.0)

```text
Verifier QR / deep link
        │
        ▼
POST /presentations  (authorizationRequestUrl)
        │  → presentationId, verifier info
        ▼
GET /presentations/{id}/credentials
        │  → queryGroups, credentialSets
        │  → user selects credentials + SD claims
        ▼
PATCH /presentations/{id}
        │  selectedCredentials: [{ queryId, selectedCredentialIds, selectedSdClaims? }]
        ▼
Redirect user to redirectUri (if returned)
```

---

## Common errors (400)

| Cause | Typical message |
|-------|-----------------|
| Unknown credential ID on submit | `Selected credential not found in session: …` |
| Unknown `queryId` | `Unknown DCQL query id '…'` |
| Too many credentials for `multiple=false` | `DCQL query '…' has multiple=false but N credential(s) were selected` |
| Invalid `credential_sets` selection | `Credential selection must satisfy exactly one option in credential_set` |
| Mixed `selectedCredentials` array types | `selectedCredentials must be either all credential ID strings or all DCQL selection objects` |

---

## Appendix A: Draft-23 (Presentation Exchange)

When the verifier uses Presentation Exchange instead of DCQL:

**GET /credentials** returns:

```json
{
  "availableCredentials": [ { "credentialId": "...", "format": "ldp_vc", "claims": [], "sdClaims": [] } ],
  "missingClaims": []
}
```

**PATCH submit:**

```json
{
  "selectedCredentials": ["cred-id-1", "cred-id-2"],
  "selectedSdClaims": {
    "cred-id-1": ["name", "dateOfBirth"]
  }
}
```

`selectedCredentials` is a **flat array of credential ID strings**, not DCQL objects.

---

## Related resources

- OpenAPI / Swagger: Mimoto API docs ([`WalletPresentationsController`](../src/main/java/io/mosip/mimoto/controller/WalletPresentationsController.java))
- Postman: [`postman-collections/MIMOTO.postman_collection.json`](./postman-collections/MIMOTO.postman_collection.json)
