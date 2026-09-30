package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

import jakarta.validation.constraints.NotBlank;

@Data
@Builder
@Schema(description = "Proof object submitted with a credential request, carrying either a JWT or CWT proof depending on issuer requirements.")
public class VCCredentialRequestProof {

    @JsonProperty("proof_type")
    @NotBlank
    @Schema(description = "Type of proof supplied in the credential request.",
            example = "jwt")
    private String proofType;

    @Schema(description = "JWT proof payload when JWT-based proof is used.")
    private String jwt;

    @Schema(description = "CWT proof payload when CBOR-based proof is used.")
    private String cwt;
}
