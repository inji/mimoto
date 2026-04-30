package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Response listing credentials that satisfy a presentation definition together with any missing claims.")
public class MatchingCredentialsResponseDTO {

    @JsonProperty("availableCredentials")
    @Schema(description = "List of credentials that match the presentation definition")
    private List<CredentialDTO> availableCredentials;

    @JsonProperty("missingClaims")
    @Schema(description = "List of claims that are required but not available in any credential",
            example = "[\"birthdate\"]")
    private Set<String> missingClaims;
}
