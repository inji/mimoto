package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(description = "Credential issue record containing the verifiable credential and audit metadata around its lifecycle.")
public class VCCredentialIssueBody {
    @NotNull(message = "Credential is required")
    @Valid
    private VCCredentialProperties credential;
    @NotBlank(message = "Credential schema ID is required and cannot be blank")
    private String credentialSchemaId;
    @NotBlank(message = "Created at is required and cannot be blank")
    private String createdAt;
    @NotBlank(message = "Created by is required and cannot be blank")
    private String createdBy;
    private String updatedAt;
    private String updatedBy;
}
