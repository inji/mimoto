package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Data
@Schema(description = "IDP authentication and consent request wrapper containing timestamp and request details.")
public class IdpAuthAndConsentDto {
    
    @NotBlank(message = "Request time is required and cannot be blank")
    @Schema(description = "Request timestamp in ISO 8601 format", 
            example = "2026-04-08T12:00:00Z")
    private String requestTime;
    
    @NotNull(message = "Request details are required")
    @Valid
    @Schema(description = "IDP authentication and consent request details")
    private AuthAndConsentRequestDto request;
}
