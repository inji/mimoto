package io.mosip.mimoto.dto.mimoto;

import io.mosip.mimoto.dto.IssuerDTO;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(description = "Resolved issuer configuration bundle used internally to combine issuer metadata, well-known metadata, and a selected supported credential.")
public class IssuerConfig {
    @NotNull(message = "Issuer DTO is required")
    @Valid
    private final IssuerDTO issuerDTO;
    @NotNull(message = "Well-known response is required")
    @Valid
    private final CredentialIssuerWellKnownResponse wellKnownResponse;
    @NotNull(message = "Credentials supported response is required")
    @Valid
    private final CredentialsSupportedResponse credentialsSupportedResponse;
}
