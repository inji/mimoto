package io.mosip.mimoto.dto.mimoto;

import io.mosip.mimoto.dto.IssuerV2DTO;
import lombok.Data;

@Data
public class IssuerConfig {
    private final IssuerV2DTO issuerDTO;
    private final CredentialIssuerWellKnownResponse wellKnownResponse;
    private final CredentialsSupportedResponse credentialsSupportedResponse;
}
