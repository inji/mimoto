package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;


@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Draft13VCCredentialRequest {

    @NotBlank
    private String format;

    @Valid
    @NotNull
    private VCCredentialRequestProof proof;

    @JsonProperty("credential_definition")
    @Valid
    @NotNull
    private VCCredentialDefinition credentialDefinition;

    private String vct;
}