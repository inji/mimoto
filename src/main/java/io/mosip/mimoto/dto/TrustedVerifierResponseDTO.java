package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;

@Data
@Schema(description = "Response returned after a trusted verifier record is created successfully.")
public class TrustedVerifierResponseDTO {
    
    @NotBlank(message = "ID is required and cannot be blank")
    @Schema(description = "Identifier of the trusted verifier record stored by Mimoto after registration completes.",
            example = "mosip.mimoto.operation")
    private String id;
}
