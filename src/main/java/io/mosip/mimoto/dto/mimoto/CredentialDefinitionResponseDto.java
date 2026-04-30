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
@Schema(description = "Credential definition metadata describing the verifiable credential types, subject claims, and JSON-LD context exposed by an issuer.")
public class CredentialDefinitionResponseDto {

    @NotEmpty(message = "Type list cannot be empty")
    @SerializedName("type")
    @JsonProperty("type")
    @Schema(description = "Ordered list of credential type identifiers declared for the verifiable credential definition.",
            example = "[\"VerifiableCredential\", \"MOSIPCredential\"]")
    private List<@NotEmpty String> type;

    @Valid
    @SerializedName("credentialSubject")
    @JsonProperty("credentialSubject")
    @Schema(description = "Map of credential subject claim definitions, where each key identifies a claim and each value describes how that claim should be displayed.")
    private Map<@NotEmpty String, @Valid CredentialDisplayResponseDto> credentialSubject;

    @SerializedName("@context")
    @JsonProperty("@context")
    @Schema(description = "JSON-LD context entries that define the semantic meaning of the credential definition.",
            example = "[\"https://www.w3.org/2018/credentials/v1\"]")
    private List<@NotEmpty String> context;
}
