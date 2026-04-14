package io.mosip.mimoto.dto.mimoto;

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
    private String credentialIssuer;

    private List<String> authorizationServers;

    private String credentialEndPoint;

    @Valid
    private Map<String, CredentialsSupportedResponse> credentialConfigurationsSupported;

    private String nonceEndpoint;

    public CredentialIssuerWellKnownResponse(String credentialIssuer, List<String> authorizationServers, String credentialEndPoint, Map<String, CredentialsSupportedResponse> credentialConfigurationsSupported) {
        this.credentialIssuer = credentialIssuer;
        this.authorizationServers = authorizationServers;
        this.credentialEndPoint = credentialEndPoint;
        this.credentialConfigurationsSupported = credentialConfigurationsSupported;
    }
}
