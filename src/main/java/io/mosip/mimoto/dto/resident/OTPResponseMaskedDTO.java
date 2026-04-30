package io.mosip.mimoto.dto.resident;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Masked OTP delivery targets returned by the resident service.")
public class OTPResponseMaskedDTO {

    @Schema(description = "Masked mobile number that received the OTP, when phone delivery was used.",
            example = "+91******3210")
    private String maskedMobile;

    @Schema(description = "Masked email address that received the OTP, when email delivery was used.",
            example = "r***a@example.com")
    private String maskedEmail;

}
