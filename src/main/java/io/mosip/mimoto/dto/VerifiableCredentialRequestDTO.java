package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import org.springframework.util.StringUtils;

@Data
@Schema(description = "Credential download request used in the OpenID4VCI flow to exchange an authorization code for a credential.")
public class VerifiableCredentialRequestDTO {
    @Schema(description = "The unique identifier of the issuer",
            example = "issuerId")
    @NotBlank(message = "issuerId cannot be blank")
    String issuer;

    @Schema(description = "The unique identifier of the credential type from the issuer well-known configuration",
            example = "MockVerifiableCredential")
    @NotBlank(message = "credentialConfigurationId cannot be blank")
    String credentialConfigurationId;

    @Schema(description = "The authorization code received from the authorization server. Required when accessToken is not provided.",
            example = "authCode")
    String code;

    @Schema(description = "The grant type for the authorization request. Required when accessToken is not provided.",
            example = "authorization_code")
    String grantType;

    @Schema(description = "The redirect URI for the authorization request. Required when accessToken is not provided.",
            example = "https://example.com/cb")
    String redirectUri;

    @Schema(description = "The code verifier used for PKCE (Proof Key for Code Exchange). Required when accessToken is not provided.",
            example = "verifier")
    String codeVerifier;

    @Schema(description = "Pre-issued access token from /v2/get-token. When present, authorization code grant fields are optional.")
    String accessToken;

    @Schema(description = "Token type for the pre-issued access token (Bearer or DPoP). Defaults to Bearer when omitted.")
    String tokenType;

    @Schema(description = "Optional c_nonce from the token response for credential proof binding.")
    String cNonce;

    @AssertTrue(message = "Either accessToken or authorization code grant (code, grantType, redirectUri, codeVerifier) must be provided")
    public boolean isTokenOrAuthorizationCodePresent() {
        if (StringUtils.hasText(accessToken)) {
            return true;
        }
        return StringUtils.hasText(code)
                && StringUtils.hasText(grantType)
                && StringUtils.hasText(redirectUri)
                && StringUtils.hasText(codeVerifier);
    }
}
