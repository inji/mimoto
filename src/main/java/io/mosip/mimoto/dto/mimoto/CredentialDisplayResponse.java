package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@Schema(description = "Display metadata for a supported credential name, locale, and logo.")
public class CredentialDisplayResponse {

    @NotBlank(message = "Name is required and cannot be blank")
    @Schema(description = "Name of the Supported Credential")
    private String name;

    @NotBlank(message = "Locale is required and cannot be blank")
    @Schema(description = "Locale of the Supported Credential")
    private String locale;

    @NotBlank(message = "Logo is required and cannot be blank")
    @Schema(description = "Logo of the Supported Credential")
    private String logo;
}
