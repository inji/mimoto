package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Authentication challenge entry returned or submitted during wallet binding and IDP flows.")
public class IdpChallangeDto {
    @NotBlank(message = "Auth factor type is required and cannot be blank")
    @Schema(description = "Auth Factory type", allowableValues = {"OTP"})
    private String authFactorType;
    @NotBlank(message = "Challenge is required and cannot be blank")
    @Schema(description = "IDP Challenge")
    private String challenge;
    @NotBlank(message = "Format is required and cannot be blank")
    @Schema(description = "IDP Format", allowableValues = {"jwt"})
    private String format;
}
