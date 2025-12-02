package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
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
public class MatchingCredentialsDTO {

    private MatchingCredentialsResponseDTO matchingCredentialsResponse;
    
    @JsonIgnore
    private List<DecryptedCredentialDTO> matchingCredentials;
}
