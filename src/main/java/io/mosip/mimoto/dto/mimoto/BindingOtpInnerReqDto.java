package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.List;

@Data
@Schema(description = "Inner request payload for wallet binding OTP generation, including the target individual identifier and delivery channels.")
public class BindingOtpInnerReqDto {

    @NotBlank(message = "Individual ID is required and cannot be blank")
    @Schema(description = "Unique individual identifier for which the wallet binding OTP should be generated.",
            example = "1289358704")
    private String individualId;
    
    @NotEmpty(message = "OTP channels list cannot be empty")
    @NotNull(message = "OTP channels are required")
    @Schema(description = "Delivery channels through which the wallet binding OTP should be sent, such as phone number or email.", 
            example = "[\"PHONE\", \"EMAIL\"]")
    private List<String> otpChannels;
}
