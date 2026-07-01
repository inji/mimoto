package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
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
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MatchingCredentialsResponseDTO {

    @JsonProperty("availableCredentials")
    @Schema(description = "Flat credential list for Draft-23")
    private List<CredentialDTO> availableCredentials;

    @JsonProperty("missingClaims")
    @Schema(description = "Missing claims for Draft-23")
    private Set<String> missingClaims;

    @JsonProperty("queryGroups")
    @Schema(description = "Per-query groups for OVP 1.0 / DCQL")
    private List<DcqlQueryGroup> queryGroups;

    @JsonProperty("credentialSets")
    @Schema(description = "Option-grouping layer from the verifier's DCQL credential_sets; synthesised from individual queries when absent in the verifier request")
    private List<CredentialSetInfo> credentialSets;
}
