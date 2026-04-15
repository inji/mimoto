package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CredentialIssuerWellKnownResponse {
    @JsonProperty("credential_issuer")
    private String credentialIssuer;

    @JsonProperty("authorization_servers")
    private List<String> authorizationServers;

    @JsonProperty("credential_endpoint")
    private String credentialEndPoint;

    @JsonProperty("credential_configurations_supported")
    private Map<String, CredentialsSupportedResponse> credentialConfigurationsSupported;

    @JsonProperty("nonce_endpoint")
    private String nonceEndpoint;

    public CredentialIssuerWellKnownResponse(String credentialIssuer, List<String> authorizationServers, String credentialEndPoint, Map<String, CredentialsSupportedResponse> credentialConfigurationsSupported) {
        this.credentialIssuer = credentialIssuer;
        this.authorizationServers = authorizationServers;
        this.credentialEndPoint = credentialEndPoint;
        this.credentialConfigurationsSupported = credentialConfigurationsSupported;
    }
}
