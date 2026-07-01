package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.openID4VP.constants.SpecVersion;
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

    @JsonIgnore
    private SpecVersion specVersion;
}
