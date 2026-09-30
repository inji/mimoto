package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Request payload used to bind a wallet using an OTP, transaction ID, and public key.")
public class WalletBindingDto {
    @NotBlank(message = "Individual ID is required and cannot be blank")
    private String individualId;
    @NotBlank(message = "OTP is required and cannot be blank")
    private String otp;
    @NotBlank(message = "Transaction ID is required and cannot be blank")
    private String transactionID;
    @NotBlank(message = "Public key is required and cannot be blank")
    private String publicKey;
}
