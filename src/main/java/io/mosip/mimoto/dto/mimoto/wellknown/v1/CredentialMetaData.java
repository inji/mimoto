package io.mosip.mimoto.dto.mimoto.wellknown.v1;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;
import java.util.Map;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

@Data
public class CredentialMetaData {

    @NotEmpty(message = "Display information must not be empty")
    @Valid
    @SerializedName("display")
    @JsonProperty("display")
    @Schema(description = "Display Properties of the Supported Credential")
    private List<@Valid CredentialSupportedDisplayResponse> display;

    @JsonInclude(NON_NULL)
    @Schema(description = "List of Claims")
    private List<Map<String, Object>> claims;
}
