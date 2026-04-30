package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@Schema(description = "Minimal JSON Web Key representation containing RSA key parameters.")
public class JwkDto {
    @NotBlank(message = "Key type is required and cannot be blank")
    @Schema(description = "Key type of the JWK.",
            example = "RSA")
    private String kty;
    @NotBlank(message = "Exponent is required and cannot be blank")
    @Schema(description = "Base64URL-encoded RSA public exponent.")
    private String e;
    @NotBlank(message = "Modulus is required and cannot be blank")
    @Schema(description = "Base64URL-encoded RSA modulus.")
    private String n;
}
