package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import java.util.Map;

@Data
@Builder
@Schema(description = "Credential definition embedded in a credential issuance request, including context, type, and credential subject claims.")
public class VCCredentialDefinition {

    @JsonProperty("@context")
    @NotEmpty(message = "Context cannot be empty")
    @Schema(description = "JSON-LD context entries to include in the credential definition.")
    private List<@NotBlank String> context;

    @NotEmpty
    @Schema(description = "Credential type identifiers to include in the definition.")
    private List<@NotBlank String> type;

    @Valid
    @Schema(description = "Credential subject claims requested for issuance.")
    private Map<String, Object> credentialSubject;

}
