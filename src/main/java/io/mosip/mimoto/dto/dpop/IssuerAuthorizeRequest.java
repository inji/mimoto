package io.mosip.mimoto.dto.dpop;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Parameters used to build the OpenID4VCI authorization URL. Mimoto generates PKCE state, code_verifier, and code_challenge. Scope comes from the issuer well-known entry for credentialConfigurationId. response_type is always code.")
public class IssuerAuthorizeRequest {

    @NotBlank(message = "redirectUri cannot be blank")
    @JsonProperty("redirectUri")
    @JsonAlias("redirect_uri")
    @Schema(example = "https://injiweb.example.com/redirect")
    private String redirectUri;

    @NotBlank(message = "credentialConfigurationId cannot be blank")
    @JsonProperty("credentialConfigurationId")
    @JsonAlias("credential_configuration_id")
    @Schema(example = "MockVerifiableCredential",
            description = "Credential configuration id from the issuer well-known. Mimoto uses its scope on the authorization URL.")
    private String credentialConfigurationId;

    @NotBlank(message = "uiLocales cannot be blank")
    @JsonProperty("uiLocales")
    @JsonAlias("ui_locales")
    @Schema(example = "en", description = "Inji Web UI language placed on the authorization URL as ui_locales")
    private String uiLocales;
}
