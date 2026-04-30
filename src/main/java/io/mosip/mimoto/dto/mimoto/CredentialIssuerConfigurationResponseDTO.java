package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
@Schema(description = "Issuer configuration response containing the credential types supported by the issuer and authorization server details required by the client.")
public class CredentialIssuerConfigurationResponseDTO {

    @JsonProperty("credentials_supported")
    @NotEmpty(message = "Credentials list cannot be empty")
    @Valid
    @Schema(description = "List of credential types supported by the issuer and the wallet-friendly display configuration for each one.")
    private List<CredentialsResponse> credentials;

    @JsonProperty("authorization_endpoint")
    @NotBlank(message = "Authorization endpoint is required and cannot be blank")
    @Schema(description = "Authorization endpoint that the client should use to authenticate and authorize the user.",
            example = "https://issuer.example.com/authorize")
    private String authorizationEndpoint;

    @JsonProperty("grant_types_supported")
    @NotEmpty(message = "Grant types supported cannot be empty")
    @Schema(description = "Grant types supported by the issuer's authorization server.",
            example = "[\"authorization_code\"]")
    private List<String> grantTypesSupported;

}
