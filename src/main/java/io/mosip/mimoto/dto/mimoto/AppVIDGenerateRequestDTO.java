package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

@Data
@Schema(description = "VID generation request payload for creating a Virtual ID.")
public class AppVIDGenerateRequestDTO {
    
    @NotBlank(message = "Individual ID is required and cannot be blank")
    @Schema(description = "Unique individual identifier (UIN or VID)", 
            example = "1289358704")
    private String individualId;
    
    @Pattern(regexp = "UIN|VID", message = "Only UIN or VID is allowed")
    @Schema(description = "Type of individual ID provided (UIN or VID)", 
            allowableValues = {"UIN", "VID"},
            example = "UIN")
    private String individualIdType;
    
    @NotBlank(message = "OTP is required and cannot be blank")
    @Schema(description = "One-time password for VID generation verification", 
            example = "123456")
    private String otp;
    
    @Schema(description = "Type of VID to generate (TEMPORARY or PERPETUAL)", 
            allowableValues = {"TEMPORARY", "PERPETUAL"},
            example = "TEMPORARY")
    private String vidType;
    
    @NotBlank(message = "Transaction ID is required and cannot be blank")
    @Schema(description = "Unique transaction identifier for tracking the request", 
            example = "1234567890")
    private String transactionID;
}
