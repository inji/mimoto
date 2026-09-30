package io.mosip.mimoto.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.ToString;

@Data
@ToString
@ApiModel(description = "Model representing a unlock user wallet request")
@Schema(description = "Unlock Wallet Request DTO", requiredProperties = {"walletPin"})
public class UnlockWalletRequestDto {
    @Schema(description = "PIN used to unlock the Wallet",
            example = "123456")
    String walletPin;

    @Schema(description = "Name of the Wallet",
            example = "My Personal Wallet")
    String walletName;
}
