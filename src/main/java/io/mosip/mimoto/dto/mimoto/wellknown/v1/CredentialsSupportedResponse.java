package io.mosip.mimoto.dto.mimoto.wellknown.v1;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.Map;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

@Data
public class CredentialsSupportedResponse {
    @NotBlank(message = "Format must not be blank")
    @Schema(description = "Format of the Credential")
    private String format;

    @NotBlank(message = "Scope must not be blank")
    @Schema(description = "Scope of the Credential")
    private String scope;

    @JsonInclude(NON_NULL)
    @Schema(description = "document Type of the Credential")
    private String doctype;

    @NotEmpty(message = "Proof types supported must not be empty")
    @Valid
    @SerializedName("proof_types_supported")
    @JsonProperty("proof_types_supported")
    @Schema(description = "List of proof types supported")
    private Map<@NotEmpty String, @Valid ProofTypesSupported> proofTypesSupported;

    @JsonInclude(NON_NULL)
    @Schema(description = "List of Claims")
    private Map<String, Object> claims;

    @SerializedName("credential_definition")
    @JsonProperty("credential_definition")
    @JsonInclude(NON_NULL)
    @Schema(description = "Credential Definition of the VC")
    private CredentialDefinitionResponseDto credentialDefinition;

    @NotNull(message = "Credential metadata must not be null")
    @Valid
    @SerializedName("credential_metadata")
    @JsonProperty("credential_metadata")
    @Schema(description = "Credential Metadata containing display properties")
    private CredentialMetaData credentialMetadata;

    @Schema(description = "Identify the type or schema of the claims included")
    private String vct;
}
