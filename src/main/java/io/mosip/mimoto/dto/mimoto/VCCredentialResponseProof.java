package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;
import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Proof block embedded inside an issued verifiable credential.")
public class VCCredentialResponseProof implements Serializable {
    @NotBlank
    @Schema(description = "Proof type used in the issued credential.",
            example = "Ed25519Signature2020")
    private String type;
    @NotBlank
    @Schema(description = "Timestamp at which the proof was created.",
            example = "2026-04-27T10:15:30Z")
    private String created;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "Purpose of the proof when provided.")
    private String proofPurpose;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "Verification method identifier for the proof.")
    private String verificationMethod;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "JWS representation of the proof when present.")
    private String jws;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "Detached proof value when present.")
    private String proofValue;

    public String getType() {
        return type;
    }
}
