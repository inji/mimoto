package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "IDP OTP request for generating one-time password.")
public class IdpOtpReqDto {
    
    @NotBlank(message = "Transaction ID is required and cannot be blank")
    @Schema(description = "Transaction identifier for OTP request", 
            example = "txn-12345-67890")
    private String transactionId;
    
    @NotBlank(message = "Individual ID is required and cannot be blank")
    @Schema(description = "Individual identifier (UIN or VID)", 
            example = "1289358704")
    private String individualId;
    
    @NotEmpty(message = "OTP channels list cannot be empty")
    @Schema(description = "List of channels for OTP delivery (EMAIL, PHONE, etc.)", 
            allowableValues = {"EMAIL", "PHONE", "SMS"},
            example = "[\"EMAIL\", \"PHONE\"]")
    private List<String> otpChannels;
}
