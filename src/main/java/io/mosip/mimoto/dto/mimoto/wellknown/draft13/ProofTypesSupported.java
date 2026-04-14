package io.mosip.mimoto.dto.mimoto.wellknown.draft13;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

@Data
public class ProofTypesSupported {

    @NotEmpty
    @JsonProperty("proof_signing_alg_values_supported")
    @SerializedName("proof_signing_alg_values_supported")
    @Schema(description = "Support Alg for proof Signing")
    private List<String> proofSigningAlgValuesSupported;
}
