package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
@Schema(description = "Normalized credential issuer configuration combining issuer metadata, supported credentials, and authorization server details.")
public class CredentialIssuerConfiguration {
    @NotBlank(message = "Credential issuer is required and cannot be blank")
    @Schema(description = "Base identifier of the credential issuer.",
            example = "https://issuer.example.com")
    private String credentialIssuer;

    @NotEmpty(message = "Authorization servers list cannot be empty")
    @Schema(description = "Authorization servers associated with the credential issuer.")
    private List<String> authorizationServers;

    @NotBlank(message = "Credential endpoint is required and cannot be blank")
    @Schema(description = "Credential endpoint exposed by the issuer.",
            example = "https://issuer.example.com/credential")
    private String credentialEndPoint;

    @NotEmpty(message = "Credential configurations supported cannot be empty")
    @Valid
    @Schema(description = "Supported credential configurations keyed by configuration identifier.")
    private Map<String, CredentialsSupportedResponse> credentialConfigurationsSupported;

    @JsonIgnoreProperties({"token_endpoint"})
    @Valid
    @Schema(description = "Resolved authorization server well-known metadata for the issuer.")
    private AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse;
}
