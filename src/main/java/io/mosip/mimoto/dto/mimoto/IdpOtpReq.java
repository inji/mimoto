package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(description = "IDP OTP request wrapper containing the request timestamp and OTP request details.")
public class IdpOtpReq {

    @NotBlank(message = "Request time is required and cannot be blank")
    @Schema(description = "Timestamp at which the OTP request was created, in ISO 8601 format.")
    private String requestTime;
    @NotNull(message = "Request details are required")
    @Valid
    @Schema(description = "Inner request payload describing the OTP generation request.")
    private IdpOtpReqDto request;
}
