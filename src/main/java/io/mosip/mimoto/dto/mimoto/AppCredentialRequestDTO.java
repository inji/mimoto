package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Data
@Schema(description = "Credential request payload for issuing a verifiable credential.")
public class AppCredentialRequestDTO {
    
    @NotBlank(message = "Individual ID is required and cannot be blank")
    @Schema(description = "Unique individual identifier (UIN or VID)", 
            example = "1289358704")
    private String individualId;
    
    @NotBlank(message = "OTP is required and cannot be blank")
    @Schema(description = "One-time password for credential request verification", 
            example = "123456")
    private String otp;
    
    @NotBlank(message = "Transaction ID is required and cannot be blank")
    @Schema(description = "Unique transaction identifier for tracking the request", 
            example = "1234567890")
    private String transactionID;
    
    @Schema(description = "Issuer identifier", 
            example = "mosip")
    private String issuer;
    
    @Schema(description = "Type of credential to issue (default: vercred)", 
            example = "vercred")
    private String credentialType = "vercred";
    
    @Schema(description = "Username or user reference identifier", 
            example = "user123")
    private String user;

    public String getIndividualId() {
        return individualId;
    }

    public String getOtp() {
        return otp;
    }

    public String getTransactionID() {
        return transactionID;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getCredentialType() {
        return credentialType;
    }

    public String getUser() {
        return user;
    }
}
