package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;


@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Credential issuance request sent to an issuer for generating a verifiable credential in a supported format.")
public class Draft13VCCredentialRequest {

    @NotBlank
    @Schema(description = "Credential format requested from the issuer.",
            example = "vc+sd-jwt")
    private String format;

    @Valid
    @NotNull
    @Schema(description = "Proof of possession or holder binding proof accompanying the credential request.")
    private VCCredentialRequestProof proof;

    @JsonProperty("credential_definition")
    @Valid
    @NotNull
    @Schema(description = "Credential definition describing the requested credential.")
    private VCCredentialDefinition credentialDefinition;

    @Schema(description = "Verifiable credential type identifier for SD-JWT based issuance flows.")
    private String vct;
}
