package io.mosip.mimoto.dto.idp;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Token request payload sent to the identity provider token endpoint.")
public class TokenRequestDTO {
    @Schema(description = "OAuth 2.0 grant type used for token exchange.",
            example = "authorization_code")
    private String grant_type;

    @Schema(description = "Authorization code received from the identity provider during the authorization flow.")
    private String code;

    @Schema(description = "Client identifier registered with the identity provider.")
    private String client_id;

    @Schema(description = "Client secret associated with the registered identity provider client.")
    private String client_secret;

    @Schema(description = "Redirect URI used during the authorization flow and repeated for token exchange.")
    private String redirect_uri;

    @Schema(description = "Type of client assertion used for token request authentication.",
            example = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    private String client_assertion_type;

    @Schema(description = "Signed client assertion JWT used to authenticate the token request.")
    private String client_assertion;
}
