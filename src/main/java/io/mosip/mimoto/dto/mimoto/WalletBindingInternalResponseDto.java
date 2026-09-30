package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Internal wallet binding response returned by the binding service with certificate material and binding expiration details.")
public class WalletBindingInternalResponseDto {
    @NotBlank(message = "Certificate is required and cannot be blank")
    @Schema(description = "Certificate of the Wallet Binding")
    private String certificate;
    @NotBlank(message = "Wallet user ID is required and cannot be blank")
    @Schema(description = "Wallet User Id of the Wallet Binding")
    private String walletUserId;
    @NotBlank(message = "Expiry date time is required and cannot be blank")
    @Schema(description = "Date Time Expiry of the Wallet Binding")
    private String expireDateTime;
}
