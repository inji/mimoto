package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
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
@JsonIgnoreProperties(ignoreUnknown = true)
@Schema(description = "Wrapper carrying a verifiable credential payload for downstream wallet or presentation processing.")
public class VerifiableCredentialResponse {

    @Valid
    @NotNull
    @Schema(description = "Verifiable credential payload.")
    private Object credential;

    private String error;

    @JsonProperty("error_description")
    private String errorDescription;

    public boolean hasError() {
        return error != null;
    }
}
