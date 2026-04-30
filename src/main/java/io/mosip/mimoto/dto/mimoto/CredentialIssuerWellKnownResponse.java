package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import io.mosip.mimoto.constant.VCSpecificationVersion;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Normalized credential issuer well-known response returned by Mimoto for legacy issuer metadata consumers.")
public class CredentialIssuerWellKnownResponse {
    @JsonProperty("credential_issuer")
    @Schema(description = "Unique identifier of the credential issuer.",
            example = "https://issuer.example.com")
    private String credentialIssuer;

    @JsonProperty("authorization_servers")
    @Schema(description = "Authorization servers associated with the credential issuer.",
            example = "[\"https://issuer.example.com\"]")
    private List<String> authorizationServers;

    @JsonProperty("credential_endpoint")
    @Schema(description = "Credential endpoint used to request or download credentials from the issuer.",
            example = "https://issuer.example.com/credential")
    private String credentialEndPoint;

    @JsonProperty("credential_configurations_supported")
    @Schema(description = "Credential configurations supported by the issuer, keyed by credential configuration identifier.")
    private Map<String, CredentialsSupportedResponse> credentialConfigurationsSupported;

    @JsonProperty("nonce_endpoint")
    private String nonceEndpoint;

    @JsonProperty("version")
    private VCSpecificationVersion version;

    public CredentialIssuerWellKnownResponse(String credentialIssuer, List<String> authorizationServers, String credentialEndPoint, Map<String, CredentialsSupportedResponse> credentialConfigurationsSupported) {
        this.credentialIssuer = credentialIssuer;
        this.authorizationServers = authorizationServers;
        this.credentialEndPoint = credentialEndPoint;
        this.credentialConfigurationsSupported = credentialConfigurationsSupported;
    }
}
