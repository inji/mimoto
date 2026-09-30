package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "IDP authentication challenge entry containing the factor type, challenge value, and format.")
public class IdpAuthChallangeDto {
    @NotBlank(message = "Auth factor type is required and cannot be blank")
    @Schema(description = "Authentication factor type required for the challenge.",
            allowableValues = {"OTP", "WLA"})
    private String authFactorType;

    @NotBlank(message = "Challenge is required and cannot be blank")
    @Schema(description = "Challenge value that must be answered or signed by the client.")
    private String challenge;

    @NotBlank(message = "Format is required and cannot be blank")
    @Schema(description = "Format of the challenge proof payload.",
            allowableValues = {"jwt"})
    private String format;
}
