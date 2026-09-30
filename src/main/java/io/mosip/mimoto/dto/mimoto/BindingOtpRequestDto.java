package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Wallet binding OTP request wrapper containing the request timestamp and inner OTP delivery details.")
public class BindingOtpRequestDto {
    @Schema(description = "Timestamp at which the wallet binding OTP request was created, in ISO 8601 format.",
            example = "2026-04-27T10:15:30Z")
    private String requestTime;

    @Valid
    @NotNull
    @Schema(description = "Wallet binding OTP request details containing the individual identifier and delivery channels.")
    private BindingOtpInnerReqDto request;
}
