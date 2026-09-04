package io.mosip.mimoto.dto.dpop;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Parameters used to build the OpenID4VCI authorization URL. Mimoto generates PKCE state, code_verifier, and code_challenge.")
public class IssuerAuthorizeRequest {

    @NotBlank(message = "redirectUri cannot be blank")
    @JsonProperty("redirectUri")
    @JsonAlias("redirect_uri")
    @Schema(example = "https://injiweb.example.com/redirect")
    private String redirectUri;

    @NotBlank(message = "scope cannot be blank")
    @Schema(example = "openid MockVerifiableCredential")
    private String scope;

    @NotBlank(message = "responseType cannot be blank")
    @JsonProperty("responseType")
    @JsonAlias("response_type")
    @Schema(example = "code")
    private String responseType;

    @NotBlank(message = "uiLocales cannot be blank")
    @JsonProperty("uiLocales")
    @JsonAlias("ui_locales")
    @Schema(example = "en", description = "Inji Web UI language placed on the authorization URL as ui_locales")
    private String uiLocales;
}
