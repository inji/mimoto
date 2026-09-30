package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "IDP consent request wrapper containing the request timestamp and the inner consent payload.")
public class IdpConsentDto {
    @NotBlank(message = "Request time is required and cannot be blank")
    @Schema(description = "Timestamp at which the consent request was created, in ISO 8601 format.")
    private String requestTime;
    @NotNull(message = "Request details are required")
    @Valid
    @Schema(description = "Inner consent request payload.")
    private IdpConsentRequestDto request;
}
