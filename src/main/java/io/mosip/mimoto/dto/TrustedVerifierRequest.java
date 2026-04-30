package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Schema(description = "Request payload used to register a verifier as trusted for the current wallet or user.")
public class TrustedVerifierRequest {
    
    @NotBlank(message = "verifierId is required and cannot be blank")
    @Size(max = 255, message = "verifierId must not exceed 255 characters")
    @Schema(description = "Unique verifier identifier, typically the OpenID client identifier or verifier base URL.",
            example = "https://injiverify.collab.mosip.net")
    private String verifierId;
}
