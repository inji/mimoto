package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Wrapper carrying a verifiable credential payload for downstream wallet or presentation processing.")
public class VerifiableCredentialResponse {

    @Valid
    @NotNull
    @Schema(description = "Verifiable credential payload.")
    private Object credential;
}
