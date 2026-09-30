package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class CredentialsResponse {

    @NotBlank(message = "Name is required and cannot be blank")
    @Schema(description = "name of the Credential")
    private String name;

    @NotBlank(message = "Scope is required and cannot be blank")
    @Schema(description = "Scope of the Credential")
    private String scope;

    @JsonProperty("display")
    @NotEmpty(message = "Display list cannot be empty")
    @Valid
    @Schema(description = "Display Properties of the Supported Credential")
    private List<CredentialDisplayResponse> display;
}
