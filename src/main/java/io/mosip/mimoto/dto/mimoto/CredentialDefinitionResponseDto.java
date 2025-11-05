package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class CredentialDefinitionResponseDto {

    @NotEmpty
    @SerializedName("type")
    @JsonProperty("type")
    @Schema(description = "Type of the Credential Definition")
    private List<@NotEmpty String> type;

    @Valid
    @SerializedName("credentialSubject")
    @JsonProperty("credentialSubject")
    @Schema(description = "Credential Subject of the VC")
    private Map<@NotEmpty String, @Valid CredentialDisplayResponseDto> credentialSubject;

    @SerializedName("@context")
    @JsonProperty("@context")
    @Schema(description = "context of the Credential Definition")
    private List<@NotEmpty String> context;
}
