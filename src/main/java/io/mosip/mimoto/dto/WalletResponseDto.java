package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
@Schema(description = "Wallet summary returned after wallet creation, unlock, or lookup operations.")
public class WalletResponseDto {
    @Schema(description = "Unique identifier of the Wallet",
            example = "123e4567-e89b-12d3-a456-426614174000")
    String walletId;

    @Schema(description = "Wallet name provided by user",
            example = "My Personal Wallet")
    String walletName;

    @JsonIgnore
    @Schema(hidden = true)
    String decryptedWalletKey;
}
