package io.mosip.mimoto.dto.idp;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Getter
@Setter
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Schema(description = "Token response returned by the identity provider after a successful token request.")
public class TokenResponseDTO {
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "OpenID Connect ID token representing the authenticated user session.")
    private String id_token;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "Type of access token returned by the authorization server.",
            example = "Bearer")
    private String token_type;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "Access token used to call protected downstream APIs.")
    private String access_token;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "Lifetime of the access token in seconds.",
            example = "300")
    private int expires_in;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "OAuth scopes granted along with the access token.")
    private String scope;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "Nonce value issued by the authorization server for proof binding or follow-up credential requests.")
    private String c_nonce;
}
