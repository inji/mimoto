package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Response returned after generating a wallet binding OTP, including the transaction identifier and masked delivery targets.")
public class BindingOtpResponseDto {
    @NotBlank(message = "Transaction ID is required and cannot be blank")
    @Schema(description = "Transaction identifier associated with the wallet binding OTP generation request.",
            example = "txn-7f3c52d8")
    private String transactionId;

    @Schema(description = "Masked email address to which the OTP was sent, when email delivery was used.",
            example = "r***a@example.com")
    private String maskedEmail;

    @Schema(description = "Masked mobile number to which the OTP was sent, when phone delivery was used.",
            example = "+91******3210")
    private String maskedMobile;
}
