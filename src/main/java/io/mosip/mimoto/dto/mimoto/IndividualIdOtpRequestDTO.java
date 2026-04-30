package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

@Data
@Schema(description = "Request payload used to trigger OTP delivery for resolving an individual identifier from an AID.")
public class IndividualIdOtpRequestDTO {
    @NotBlank(message = "AID is required and cannot be blank")
    @Schema(description = "Application or account identifier for which the individual ID should be resolved.")
    private String aid;

    @NotEmpty(message = "OTP channel list cannot be empty")
    @Schema(description = "OTP delivery channels requested for the AID lookup.",
            allowableValues = {"EMAIL", "PHONE", "SMS"})
    private List<String> otpChannel;

    @NotBlank(message = "Transaction ID is required and cannot be blank")
    @Schema(description = "Transaction identifier used to track the individual ID OTP request.")
    private String transactionID;
}
