# Support for OpenID4VCI Issuance spec 1.0 in INJI Web wallet

This document outlines the changes expected in the INJI Web wallet to support the VCI Issuance spec 1.0, which is the latest version of the OpenID4VCI specification. The document also highlights the changes in the specification compared to draft 13 and the expected changes in mimoto, which is the reference implementation for OpenID4VCI specification.

## Key Changes in OpenID4VCI specific 1.0 which impacts wallet implementation:
- `nonce_endpoint` - optional param is introduced in the well-known response. If the field is present in response, wallet has to fetch the credential from the nonce_endpoint during the proof creation and embed it in the proof. If the field is missing, c_nonce claim should not be added in proof JWT sent in the credential request.
- `credential_configurations_supported` -> `display` object is now moved to `credential_configurations_supported` -> `credential_metadata` -> `display`
- Credential request is now format-agnostic, with the following structure : 

    ```json
    {
      "credential_configuration_id": "org.iso.18013.5.1.mDL",
      "proofs": {
        "jwt": [
          "<jwt_proof>"
        ]
      }
    }
    ```
- Credential response structure is changed to support multiple credentials in response, with the following structure :

    ```json
    {
      "credentials": [
        {
          "credential": "<credential-jwt-or-ldp-vc-placeholder>"
        }
      ]
    }
    ```

Guidelines for implementation in INJI Web wallet:  
- We will be supporting both draft 13 and v1.0 specification
- The existing credential download code will be refactored to be made extensible to support future versions of the specification as well. 
- The flow will be designed in such a way that the version detection logic will be implemented at the beginning of the flow and based on the version detected, the respective flow will be triggered.

### Changes expected in mimoto :

1. Issuer configuration fetch logic change, since we want to support both draft 13 and v1.0 VCI specification
  - Need to have version detection logic, should be checked in the following sequence in received well-known response :
     - If `nonce_endpoint fields` exists in the response and is not empty, version will be v1
     - if `credential_configurations_supported` -> `credential_metadata` object exists, version will be v1
     - if `credential_configurations_supported` -> `display`, version will be draft13
     - Default to v1
  - Well-known parser factory has to be introduced, to support parsing of both draft 13 and v1.0 specification
  - The well-known response will be parsed using their separate DTOs and validated.
  - The final values will be mapped to a common DTO, so that the rest of the flow remains unaffected by the changes in the specification. This will also help in supporting future versions of the specification with minimal changes in the code.
2. VC Download handler to be introduced for each version of the specification, to handle the respective credential request and response structure. The handler will be responsible for :
  - Extracting nonce from the nonce_endpoint in case of v1.0 specification and embedding it in the proof JWT sent in credential request. The nonce for draft 13 will be extracted from token response and embedded in the proof JWT as c_nonce.
  - Sending the credential request to the issuer
  - Handling the credential response based on the respective specification
  - Returning the credential to the caller in a standard format(as an array of credential), so that the rest of the flow remains unaffected by the changes in the specification.
3. The PDF download flow will still extract the first credential from the array of credentials and generate the PDF based on that, so that there is no change expected in the PDF generation flow.
4. For logged-in users, all the credentials will be stored in the wallet and same will be returned in the API response.

### Open Questions : 
1. Should we modify the wallet credential download API to return an array of credentials instead of a single credential without maintaining backward compatibility?

### Class structure : 

- Factory class to be introduced for version detection and parsing of well-known response based on the version detected. The factory class will be called in the IssuerConfigUtil, which is responsible for fetching and parsing the issuer configuration. 
- The IssuerConfigUtil will return a common DTO, which will be used in the rest of the flow. This will help in minimizing the changes in the code and also support future versions of the specification with minimal changes.

```text
    ┌──────────────────────────────────────────────────────────────┐
    │                  IssuersServiceImpl                          │
    │               (High-level orchestration)                     │
    └─────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
    ┌──────────────────────────────────────────────────────────────┐
    │                  IssuerConfigUtil                            │
    │  ┌───────────────────────────────────────────────────┐       │
    │  │  getIssuerWellknown(url)                          │       │
    │  │    ├─> VCSpecVersionDetector (defaults to V1)     │       │
    │  │    ├─> WellknownParserFactory                     │       │
    │  │    └─> Return CredentialIssuerWellKnownResponse   │       │
    │  └───────────────────────────────────────────────────┘       │
    └─────────────────────────┬────────────────────────────────────┘
                              │
                  ┌───────────┴───────────┐
                  ▼                       ▼
            ┌─────────────────┐    ┌──────────────────┐
            │Draft13Wellknown │    │ WellknownParser  │
            │    Parser       │    │  (V1 - default)  │
            └─────────────────┘    └──────────────────┘
```

Interface for well-known response parser : 

```java
public interface WellknownResponseParser {

    /**
     * Returns the specification version supported by this parser
     */
    VCSpecificationVersion getSupportedVersion();
    
    /**
     * Parses the wellknown response JSON
     */
    CredentialIssuerWellKnownResponse parse(String jsonResponse) throws IOException;
    
    /**
     * Validates the parsed wellknown response
     */
    void validate(CredentialIssuerWellKnownResponse response, Validator validator) 
        throws InvalidWellknownResponseException;
}
```


- VC Download handler class structure : 

```text

    ┌──────────────────────────────────────────────────────────────┐
    │              VCDownloadHandlerFactory                        │
    │         getHandler(version) → returns handler                │
    └─────────────────────────┬────────────────────────────────────┘
                              │
                  ┌───────────┴───────────┐
                  ▼                       ▼
         ┌──────────────────────┐    ┌──────────────────────┐
         │ Draft13VC            │    │ VCDownloadHandler    │
         │ DownloadHandler      │    │  (V1 - default)      │
         │                      │    │                      │
         |downloadCredential()  │    │ downloadCredential() │
         │ • Get cNonce         │    │ • Get cNonce         │
         │ (from token response)│    │ (from nonce endpoint)│
         │ • Build proof        │    │ • Build proof        │
         │ • Build request      │    │ • Build request      │
         │ • POST endpoint      │    │ • POST endpoint      │
         │ • Parse response     │    │ • Parse response     │
         └────────┬─────────────┘    └──────────┬───────────┘
                  │                             │
                  └────────────┬────────────────┘
                               ▼
                      ┌──────────────────────┐
                      │  Common Response DTO │
                      │ VCCredentialResponse │
                      │  - credentials[]     │
                      │  (normalized array)  │
                      └──────────────────────┘
```

Interface :

```java

public interface VCDownloadHandler {

    /**
     * Returns the specification version supported by this handler
     */
    VCSpecificationVersion getSupportedVersion();

    /**
     * Downloads credential from issuer and returns normalized response
     *
     * Responsibilities:
     * 1. Retrieve nonce only when required by spec version/issuer metadata
     * 2. Build proof JWT and include c_nonce only when nonce is available/required
     * 3. Construct version-specific credential request
     * 4. POST request to credential endpoint
     * 5. Parse response and normalize to common DTO
     *
     * @param tokenResponse Token response from IdP
     * @param credentialConfigurationId Credential configuration ID
     * @param credentialConfig Credential configuration from wellknown
     * @param wellKnownResponse Issuer wellknown response
     * @param issuerDTO Issuer details
     * @param walletId Wallet ID for proof binding
     * @param base64Key Wallet key for proof signing
     * @param isLoginFlow indicates if the user is logged in or not
     * @return VCCredentialResponse with normalized credentials array
     */
    VCCredentialResponse downloadCredential(
            TokenResponseDTO tokenResponse,
            String credentialConfigurationId,
            CredentialsSupportedResponse credentialConfig,
            CredentialIssuerWellKnownResponse wellKnownResponse,
            IssuerDTO issuerDTO,
            String walletId,
            String base64Key,
            boolean isLoginFlow
    ) throws Exception;
}
```


### References
[OpenID4VCI 1.0 specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)