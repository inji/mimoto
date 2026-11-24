package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

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

    @Schema(description = "The authorization code received from the authorization server",
            example = "authCode")
    @NotBlank(message = "code cannot be blank")
    String code;
}
