package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@Schema(description = "Response returned after a presentation authorization request is processed, including the local presentation session ID and verifier details.")
public class VPResponseDTO {

    @Schema(description = "Unique identifier for the Verifiable Presentation",
            example = "123e4567-e89b-12d3-a456-426614174000")
    String presentationId;

    @JsonProperty("verifier")
    @Schema(description = "Information about the Verifier who sent the Verifiable Presentation request")
    VerifiablePresentationVerifierDTO verifiablePresentationVerifierDTO;

}
