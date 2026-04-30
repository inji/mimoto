package io.mosip.mimoto.dto;

import io.mosip.mimoto.model.WalletLockStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;


@Data
@AllArgsConstructor
@Builder
@Schema(description = "Wallet summary returned when listing all wallets belonging to the current user.")
public class WalletDetailsResponseDto {
    @Schema(description = "Unique identifier of the Wallet",
            example = "123e4567-e89b-12d3-a456-426614174000")
    String walletId;
    @Schema(description = "Wallet name provided by user",
            example = "My Personal Wallet")
    String walletName;
    @Schema(description = "Wallet status indicating if it is locked or unlocked",
            example = "temporarily_locked")
    WalletLockStatus walletStatus;
}
