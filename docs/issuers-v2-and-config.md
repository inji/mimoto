# Issuers V2 API and mimoto-issuers-config

This document describes the **Issuers V2** endpoints, how to configure **mimoto-issuers-config.json**, and how **both the old and new issuer schema** are supported.

---

## V2 Endpoints

The V2 issuer API provides a minimal, configuration-only view of issuers. It does **not** call any issuer well-known endpoints, so it is fast and does not depend on external credential issuers being reachable.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v2/issuers` | List all onboarded issuers (with optional `?search=...` filter) |
| GET | `/v2/issuers/{issuer-id}` | Get a single issuer by ID |

### V2 features

- **Configuration-only response**  
  Response data comes only from **mimoto-issuers-config.json**. No remote well-known calls are made. Fields returned include: `issuer_id`, `protocol`, `display`, `client_id`, `token_endpoint`, `client_alias`, `qr_code_type`, `enabled`, `credential_issuer_host`.

- **Optional search**  
  List endpoint supports a query parameter: `GET /v2/issuers?search=Sunbird`. Issuers are filtered by display title (case-insensitive).

- **Same config, both APIs**  
  The same config file is used for:
  - **V1** (`/issuers`, `/issuers/{issuer-id}`): returns an enriched response that may include well-known–derived fields (e.g. `wellknown_endpoint`, `authorization_audience`, `proxy_token_endpoint`). V1 may call each issuer’s well-known endpoint.
  - **V2** (`/v2/issuers`, `/v2/issuers/{issuer-id}`): returns only the issuer entries from config; no well-known fetch.

- **Error handling**  
  V2 returns `400` when the config is not accessible and `404` for an invalid `issuer-id` on the single-issuer endpoint.

---

## Configuring mimoto-issuers-config.json

### Location and property

- **Property:** `mosip.openid.issuers`  
- **Default (e.g. local):** `mimoto-issuers-config.json` (loaded from classpath, e.g. `src/main/resources/`).  
- **Environment / Docker:** The same property can point to an external or mounted file path, depending on your deployment.

Example in `application-local.properties`:

```properties
mosip.openid.issuers=mimoto-issuers-config.json
```

### File structure

The file must be valid JSON with a top-level key **`issuers`**, which is an array of issuer objects:

```json
{
  "issuers": [
    {
      "issuer_id": "MyIssuer",
      "protocol": "OpenId4VCI",
      "display": [ ... ],
      "client_id": "...",
      "token_endpoint": "https://...",
      "client_alias": "...",
      "qr_code_type": "OnlineSharing",
      "enabled": "true",
      "credential_issuer_host": "https://..."
    }
  ]
}
```

### Required fields (all schemas)

Every issuer entry must include:

| Field | Type | Description |
|-------|------|-------------|
| `issuer_id` | string | Unique identifier of the issuer |
| `protocol` | string | `"OTP"` or `"OpenId4VCI"` |
| `display` | array | At least one display object with `name`, `logo` (with `url`, `alt_text`), `title`, `description`, `language` |
| `client_id` | string | OIDC client ID |
| `token_endpoint` | string | Valid URL for the token endpoint |
| `client_alias` | string | Client alias in keyStore |
| `qr_code_type` | string | `"OnlineSharing"`, `"EmbeddedVC"`, or `"None"` |
| `enabled` | string | `"true"` or `"false"` |
| `credential_issuer_host` | string | Valid URL of the credential issuer host |

Validation runs at startup (e.g. via `IssuersValidationConfig`). Invalid or missing required fields will cause startup failure with a clear message.

---

## Old vs new schema (both supported)

**Both the old and new issuer schema work** with the same application and config file.

### New (minimal) schema

Only the **required** fields above are needed. This is enough for **V2** and for **V1** to resolve well-known at runtime from `credential_issuer_host`:

- `issuer_id`, `protocol`, `display`, `client_id`, `token_endpoint`, `client_alias`, `qr_code_type`, `enabled`, `credential_issuer_host`

Example (minimal):

```json
{
  "issuers": [
    {
      "issuer_id": "StayProtected",
      "protocol": "OpenId4VCI",
      "display": [
        {
          "name": "StayProtected Insurance",
          "logo": { "url": "https://...", "alt_text": "Logo" },
          "title": "Download StayProtected Insurance Credentials",
          "description": "Download insurance credential",
          "language": "en"
        }
      ],
      "client_id": "mpartner-default-mimoto-insurance-oidc",
      "token_endpoint": "https://api.example.com/v1/mimoto/get-token/StayProtected",
      "client_alias": "mpartner-default-mimoto-insurance-oidc",
      "qr_code_type": "OnlineSharing",
      "enabled": "true",
      "credential_issuer_host": "https://injicertify-insurance.example.com"
    }
  ]
}
```

### Old (extended) schema

You can still use the **extended** schema that includes optional fields previously used by the UI or tooling. These are **not** required for V2 or for V1; if present, they may be used or ignored depending on the endpoint:

- `wellknown_endpoint`
- `redirect_uri`
- `authorization_audience`
- `proxy_token_endpoint`
- `credential_issuer`

Example (extended):

```json
{
  "issuers": [
    {
      "issuer_id": "Mock",
      "protocol": "OpenId4VCI",
      "display": [ ... ],
      "client_id": "wallet-demo",
      "wellknown_endpoint": "https://.../.well-known/openid-credential-issuer",
      "redirect_uri": "io.mosip.residentapp.inji://oauthredirect",
      "authorization_audience": "https://...",
      "token_endpoint": "https://...",
      "proxy_token_endpoint": "https://...",
      "client_alias": "wallet-demo-client",
      "qr_code_type": "OnlineSharing",
      "enabled": "true",
      "credential_issuer": "Mock",
      "credential_issuer_host": "https://..."
    }
  ]
}
```

- **V2** ignores these extra fields and returns only the core issuer fields from config.
- **V1** may use well-known at runtime (from `credential_issuer_host`) to fill in `authorization_audience`, `proxy_token_endpoint`, etc.; any values in the config for these may be overridden or used as fallbacks depending on implementation.

You can **mix** minimal and extended entries in the same `issuers` array; both schemas are valid.

---

## Summary

| Topic | Summary |
|-------|---------|
| **V2 API** | `GET /v2/issuers` and `GET /v2/issuers/{issuer-id}`; config-only, no well-known calls. |
| **Config file** | Set `mosip.openid.issuers` (e.g. `mimoto-issuers-config.json`); structure is `{ "issuers": [ ... ] }`. |
| **Required fields** | `issuer_id`, `protocol`, `display`, `client_id`, `token_endpoint`, `client_alias`, `qr_code_type`, `enabled`, `credential_issuer_host`. |
| **Schema compatibility** | Both **old (extended)** and **new (minimal)** issuer schemas work; extra fields are allowed and ignored by V2. |

For OpenAPI details, see `docs/api-documentation-openapi.json` (paths `/v2/issuers` and `/v2/issuers/{issuer-id}`). For Postman, use the **Issuers** folder requests: **get Issuers List (V2)**, **get Issuer by ID (V2)**, and **Search Issuers List (V2)**.
