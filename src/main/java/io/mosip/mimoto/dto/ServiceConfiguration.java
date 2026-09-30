package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Service endpoint configuration used by OpenID and credential issuance flows.")
public class ServiceConfiguration {
    @Schema(description = "Authorization endpoint URL.")
    String authorizationEndpoint;
    @Schema(description = "Token endpoint URL.")
    String tokenEndpoint;
    @Schema(description = "Credential endpoint URL.")
    String credentialEndpoint;
    @Schema(description = "Audience value expected by the credential service.")
    String credentialAudience;
}
