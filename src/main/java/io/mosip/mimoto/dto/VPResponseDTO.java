package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class VPResponseDTO {

    @Schema(description = "Unique identifier for the Verifiable Presentation")
    String presentationId;

    @JsonProperty("verifier")
    @Schema(description = "Information about the Verifier who sent the Verifiable Presentation request")
    VerifiablePresentationVerifierDTO verifiablePresentationVerifierDTO;

}
