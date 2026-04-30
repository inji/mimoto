package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * DTO that contains both the matching credentials response and the wallet credentials from repository.
 * This helps avoid duplicate database hits when both pieces of data are needed.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Internal DTO holding both the matching-credentials response and the decrypted credential records.")
public class MatchingCredentialsDTO {

    @Schema(description = "Presentation-definition matching result prepared for the API response.")
    private MatchingCredentialsResponseDTO matchingCredentialsResponse;
    
    @JsonIgnore
    private List<DecryptedCredentialDTO> matchingCredentials;
}
