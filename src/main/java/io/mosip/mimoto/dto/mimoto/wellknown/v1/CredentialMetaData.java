package io.mosip.mimoto.dto.mimoto.wellknown.v1;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import io.mosip.mimoto.dto.mimoto.CredentialSupportedDisplayResponse;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

@Data
public class CredentialMetaData {

    @NotEmpty(message = "Display information must not be empty")
    @Valid
    @SerializedName("display")
    @JsonProperty("display")
    @Schema(description = "Display Properties of the Supported Credential")
    private List<@Valid CredentialSupportedDisplayResponse> display;
    
}
