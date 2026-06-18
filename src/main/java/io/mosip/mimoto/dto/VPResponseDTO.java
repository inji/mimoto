package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.mimoto.constant.SpecVersion;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class VPResponseDTO {

    @Schema(description = "Unique identifier for the Verifiable Presentation")
    private String presentationId;

    @JsonProperty("verifier")
    @Schema(description = "Information about the Verifier who sent the Verifiable Presentation request")
    private VerifiablePresentationVerifierDTO verifiablePresentationVerifierDTO;

    @Schema(description = "Detected OpenID4VP spec version for this session")
    private SpecVersion specVersion;
}
