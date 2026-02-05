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
public class EsignetBindingOtpDto {
    @Schema(description = "Request Time of the Binding OTP")
    private String requestTime;
    @Valid
    @NotNull
    @Schema(description = "Binding OTP Request")
    private BindingOtpInnerReqDto request;
}
