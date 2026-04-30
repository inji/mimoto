package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "IDP authentication request wrapper containing request timestamp and details.")
public class IdpAuthRequestDto {
    
    @NotBlank(message = "Request time is required and cannot be blank")
    @Schema(description = "Request timestamp in ISO 8601 format", 
            example = "2026-04-08T12:00:00Z")
    private String requestTime;
    
    @NotNull(message = "Request details are required")
    @Valid
    @Schema(description = "IDP authentication request details")
    private IdpAuthInternalRequestDto request;
}
