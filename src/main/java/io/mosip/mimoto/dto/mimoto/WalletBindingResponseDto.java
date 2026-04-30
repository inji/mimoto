package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Response returned after wallet binding succeeds, containing the binding certificate reference and encrypted binding material.")
public class WalletBindingResponseDto {
    @NotBlank(message = "Certificate is required and cannot be blank")
    @Schema(description = "Certificate or certificate identifier associated with the wallet binding response.",
            example = "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----")
    private String certificate;

    @NotBlank(message = "Encrypted wallet binding ID is required and cannot be blank")
    @Schema(description = "Encrypted wallet binding identifier produced by the binding service and meant for secure wallet-side processing.",
            example = "eyJhbGciOiJSUzI1NiJ9...")
    private String encryptedWalletBindingId;

    @NotBlank(message = "Expiry date time is required and cannot be blank")
    @Schema(description = "Expiry timestamp after which the binding response or binding token is no longer valid.",
            example = "2026-04-27T10:30:00Z")
    private String expireDateTime;

    @Schema(description = "Key thumbprint associated with the binding material.",
            example = "4f9c2bd8c1e7aa45")
    private String thumbprint;

    @Schema(description = "Identifier of the key associated with the wallet binding response.",
            example = "wallet-binding-key-01")
    private String keyId;
}
