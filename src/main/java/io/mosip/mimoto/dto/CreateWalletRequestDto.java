package io.mosip.mimoto.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.ToString;

@Data
@ToString
@ApiModel(description = "Model representing a create user wallet request")
@Schema(description = "Create Wallet Request DTO", requiredProperties = {"walletPin", "confirmWalletPin"})
public class CreateWalletRequestDto {
    @Schema(description = "PIN used to unlock the Wallet",
            example = "123456")
    String walletPin;

    @Schema(description = "Re-entered PIN used to confirm the Wallet PIN",
            example = "123456")
    String confirmWalletPin;

    @Schema(description = "Name of the Wallet",
            example = "My Personal Wallet")
    String walletName;
}
