package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DcqlCredentialSelection {

    @JsonProperty("queryId")
    private String queryId;

    @JsonProperty("selectedCredentialIds")
    private List<String> selectedCredentialIds;

    @JsonProperty("selectedSdClaims")
    private Map<String, List<String>> selectedSdClaims;
}
