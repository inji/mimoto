package io.mosip.mimoto.dto.mimoto;

import java.util.List;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

@Data
@Schema(description = "OTP request payload for credential download.")
public class AppOTPRequestDTO {
    
    @NotNull(message = "Individual ID is required")
    @Schema(description = "Unique individual identifier (UIN or VID)", 
            example = "1289358704")
    private String individualId;
    
    @Pattern(regexp = "UIN|VID", message = "Only UIN or VID is allowed")
    @Schema(description = "Type of individual ID provided (UIN or VID)", 
            allowableValues = {"UIN", "VID"},
            example = "UIN")
    private String individualIdType;
    
    @NotEmpty(message = "OTP channel list cannot be empty")
    @NotNull(message = "OTP channel is required")
    @Schema(description = "Channels through which OTP should be delivered (EMAIL, PHONE, etc.)", 
            allowableValues = {"EMAIL", "PHONE", "SMS"},
            example = "[\"EMAIL\", \"PHONE\"]")
    private List<String> otpChannel;
    
    @NotNull(message = "Transaction ID is required")
    @Schema(description = "Unique transaction identifier for tracking the request", 
            example = "1234567890")
    private String transactionID;
}
