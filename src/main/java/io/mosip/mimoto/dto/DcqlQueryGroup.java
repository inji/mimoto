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
public class DcqlQueryGroup {

    @JsonProperty("queryId")
    @Schema(description = "DCQL credential query id (dcql_query.credentials[i].id)")
    private String queryId;

    @JsonProperty("multiple")
    @Schema(description = "Whether more than one credential may be selected for this query")
    private boolean multiple;

    @JsonProperty("availableCredentials")
    private List<CredentialDTO> availableCredentials;

    @JsonProperty("missingClaims")
    private Set<String> missingClaims;
}
