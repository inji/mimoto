# Google OAuth2 Login Integration Guide

## Overview
This documentation explains the implementation of the login feature using Google OAuth2 login. It also covers the authentication mechanism for APIs in : 
 - `UsersController`
 - `WalletController`
 - `WalletCredentialsController`.

---

## Prerequisites
Before you begin, ensure you have:
1. **A Google Developer Console account.**
2. **A project created in the Google Developer Console.**
3. **OAuth2 enabled for the project.**
4. **A Client ID and Client Secret generated.**
---

## Google OAuth2 Integration Steps

1. **Configure OAuth2 Login**:
    - Google client ID and secret in `application-default.properties`:
      ```
      spring.security.oauth2.client.registration.google.client-id=${mosip.injiweb.google.client.id}
      spring.security.oauth2.client.registration.google.client-secret=${mosip.injiweb.google.client.secret}
      ```
    -  Make sure value of `mosip.injiweb.google.client.id` and `mosip.injiweb.google.client.secret` are set in the environment.
2. **Authorized Host URL**:
    - Register the base domain of your mimoto in Google Developer Console, e.g., `https://your-mimoto-domain`.

3. **Redirect URI**:
    - Under Authorized redirect URIs in Google Developer Console, add:
      `https://<your-mimoto-domain>/oauth2/callback/*`
      Replace `<your-mimoto-domain>` with your application's domain.
    - Ensure the redirect URI matches the one configured in the Google Developer Console.
---

## Execution Flow

### Phase 1: Login Initiation
1.  **User Action**: The user clicks the "Continue with Google" button on the Inji Web landing page.
2.  **Redirection**: Inji Web redirects the browser to Mimoto's authorization endpoint.
3.  **IdP Handshake**: Mimoto's security filter chain handles the request and redirects the user to the IDP's consent screen.

### Phase 2: Authorization & Token Exchange
1.  **Callback**: After account selection, the IDP redirects back to Mimoto with an authorization code.
2.  **Token Retrieval**: Spring Security internally exchanges this code for an `access_token` and fetches the user profile (Name, Email, Picture).

### Phase 3: User Onboarding
After successful login, the system checks if the user already exists. If not, it creates a new internal identity and securely stores the user’s profile information.

An internal `userId` is generated to uniquely identify the user within the system. This ensures the system is not tightly coupled to a specific identity provider and can support multiple providers in the future.

1.  **Metadata Check**: Mimoto checks the `user_metadata` table.
2.  **Creation/Update**: If new, it generates a unique internal **UUID** (`userId`) and encrypts the PII (Name, Email, Picture). Else the existing record is used.
3.  **Enrichment**: The internal `userId` is added to the security principal for downstream use.

### Phase 4: Success/Failure Handling
1.  **Success**: Mimoto saves the `userId` and user metadata into the **HTTPSession** and redirects the user to the passcode page.
2.  **Failure**: Mimoto captures errors (timeouts, denied consent), encodes them, and redirects back to the UI with error parameters.
---

## Sequence Diagram
### Google Login Flow
```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant mimoto
    participant GoogleOAuth2
    participant Redis

    User->>Browser: Navigate to Login Page
    Browser->>mimoto: Request Login
    mimoto->>GoogleOAuth2: Redirect to Google Login
    GoogleOAuth2->>User: Prompt for Credentials
    User->>GoogleOAuth2: Enter Credentials
    GoogleOAuth2->>mimoto: Send Authorization Code
    mimoto->>GoogleOAuth2: Exchange Code for Access Token
    GoogleOAuth2->>mimoto: Return Access Token & User Info
    mimoto->>Redis: Store Session ID and User Metadata
    mimoto->>Browser: Set Session ID in Cookie / Response
    Browser->>User: Redirect to Dashboard
 ```    
### Authenticated API Access Flow
```mermaid
 sequenceDiagram
    participant User
    participant Browser
    participant mimoto
    participant Redis

    User->>Browser: Request API
    Browser->>mimoto: Send API Request with Session ID
    mimoto->>Redis: Validate Session ID
    Redis->>mimoto: Return User Metadata
    mimoto->>Browser: Respond with Data
```
---
## Key Points
### Session-Based Authentication:
- On successful login, a session ID is generated and stored in Redis.
- All APIs in UsersController, WalletController, and WalletCredentialsController validate the session ID stored in Redis.

### Integration Points in Application
### Component	Responsibility

| **Component**                  | **Responsibility**                                                                 |
|--------------------------------|-------------------------------------------------------------------------------------|
| `Config`                       | Configures OAuth2 login, session management, and security settings.                |
| `OAuth2AuthenticationSuccessHandler` | Handles successful authentication, stores user metadata in the session, and redirects to the dashboard. |
| `OAuth2AuthenticationFailureHandler` | Handles authentication failures, logs errors, and redirects to the login page with error details. |
| `CustomOAuth2UserService`      | Retrieves and processes user information from the OAuth2 provider.                 |
| `TokenAuthController`          | Provides API for token-based authentication and session creation.                  |
| `UsersController`              | Manages user profile retrieval using session-based authentication.                 |
| `WalletsController`            | Handles wallet creation, unlocking, and deletion using session-based authentication. |
| `WalletCredentialsController`  | Manages credential download, retrieval, and deletion for wallets.                  |

### Configuration & Switching Providers
If you want to change your IDP from Google to another provider, you need to update the following properties.

**Important:** When switching, you should replace the word `google` in the property keys with your new provider's **Registration ID** (e.g., `okta`, `facebook`, or `keycloak`). Refer `application-default.properties` for the property keys.

#### A. Client Registration (in `application-default.properties`)
These properties identify the application to the IDP:
* `spring.security.oauth2.client.registration.{registrationId}.client-id` – Client ID from your new provider.
* `spring.security.oauth2.client.registration.{registrationId}.client-secret` – Client secret from your new provider.
* `spring.security.oauth2.client.registration.{registrationId}.scope` – Scopes supported (e.g., `profile, email`).
* `spring.security.oauth2.client.registration.{registrationId}.client-name` – Human-readable name for the login button.

#### B. Provider Endpoints (in `application-default.properties`)
These tell Mimoto where to send the user for authentication:
* `spring.security.oauth2.client.provider.{registrationId}.authorization-uri` – The provider's login URL.
* `spring.security.oauth2.client.provider.{registrationId}.token-uri` – The URL to exchange codes for tokens.
* `spring.security.oauth2.client.provider.{registrationId}.user-info-uri` – The URL to fetch user profile details.
* `spring.security.oauth2.client.provider.{registrationId}.jwk-set-uri` – The URI for the provider's public keys to validate tokens.

#### C. Attribute Mappings (in `application-default.properties`)
These map the IDP's response fields to Inji’s internal metadata:
* `spring.security.oauth2.client.provider.{registrationId}.userNameAttribute` – The unique identifier (e.g., `sub`).
* `spring.security.oauth2.client.provider.{registrationId}.nameAttribute` – Field for the user's full name.
* `spring.security.oauth2.client.provider.{registrationId}.emailAttribute` – Field for the user's email.
* `spring.security.oauth2.client.provider.{registrationId}.pictureAttribute` – Field for the profile picture URL.

#### D. Global Properties (in `application.properties`)
* `googleIdToken` – Update this URL to point to the new provider's token endpoint


### Errors
When login fails, Mimoto uses **302 Redirects** to pass error context back to Inji Web.
Direct requests to protected APIs made without a valid session will return a standard 401 Unauthorized response.

| Scenario           | HTTP Status | Description                                                                           |
|--------------------|-------------|---------------------------------------------------------------------------------------|
| **Login Success**  | 302         | Redirects to `${mosip.inji.web.authentication.success.redirect.url}/user/passcode`.   |
| **Consent Denied** | 302         | Redirects to `${injiWebUrl}/?status=error&error_message=...`.                         |
| **IDP Timeout**    | 302         | Redirects to `${injiWebUrl}/?status=error&error_message=...`. IDP servers unreachable. |
| **Unauthorized**   | 401         | Returned if a user attempts to access protected APIs without an active session.       |