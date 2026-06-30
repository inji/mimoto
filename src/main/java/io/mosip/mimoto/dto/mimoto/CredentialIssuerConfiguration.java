package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CredentialIssuerConfiguration {
    private String credentialIssuer;

    private List<String> authorizationServers;

    private String credentialEndPoint;

    private Map<String, CredentialsSupportedResponse> credentialConfigurationsSupported;

    @JsonIgnoreProperties({"token_endpoint"})
    private AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse;
}