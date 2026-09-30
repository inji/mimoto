package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Response payload containing the OpenID4VP authorization request URL.")
public class VPAuthorizationRequestDTO {
    @Schema(description = "Authorization request URL that the wallet or browser should open to continue the OpenID4VP flow.")
    private String authorizationRequestUrl;
}
