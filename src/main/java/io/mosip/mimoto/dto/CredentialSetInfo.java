package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialSetInfo {

    @JsonProperty("required")
    @Schema(description = "True when the user must satisfy one option in this section")
    private boolean required;

    @JsonProperty("options")
    @Schema(description = "List of options; each option is a list of queryIds that must all be presented together")
    private List<List<String>> options;
}
