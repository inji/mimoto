package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CredentialIssuerDisplayResponse {

    @SerializedName("name")
    @JsonProperty("name")
    @Schema(description = "Name of the Credential Issuer")
    private String name;

    @SerializedName("locale")
    @JsonProperty("locale")
    @Schema(description = "Locale of the Credential Issuer")
    private String locale;
}
