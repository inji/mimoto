package io.mosip.mimoto.dto.mimoto;

import com.nimbusds.jose.jwk.JWK;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.List;

@Data
@Schema(description = "Wallet binding inner request DTO containing authentication challenge details.")
public class WalletBindingInnerRequestDto {
    
    @NotBlank(message = "Individual ID is required and cannot be blank")
    @Schema(description = "Individual Id of the Wallet Binding", 
            example = "1289358704")
    private String individualId;
    
    @NotEmpty(message = "Challenge list cannot be empty")
    @Valid
    @Schema(description = "Challenge List of the Wallet Binding", 
            example = "[]")
    private List<IdpChallangeDto> challengeList;
    
    @NotNull(message = "Public key is required")
    @Valid
    @Schema(description = "Public Key of the Wallet Binding in JWK format")
    private JwkDto publicKey;
    
    @NotBlank(message = "Auth Factor Type is required and cannot be blank")
    @Schema(description = "Auth Factor Type of the Wallet Binding", 
            allowableValues = {"WLA"},
            example = "WLA")
    private String authFactorType;
    
    @NotBlank(message = "Format is required and cannot be blank")
    @Schema(description = "Format of the Wallet Binding", 
            allowableValues = {"jwt"},
            example = "jwt")
    private String format;
}
