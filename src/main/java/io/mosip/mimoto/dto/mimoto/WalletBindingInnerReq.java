package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.List;

@Data
@Schema(description = "Wallet binding inner request payload containing challenge and authentication details.")
public class WalletBindingInnerReq {

    @NotBlank(message = "Individual ID is required and cannot be blank")
    @Schema(description = "Individual Id of the wallet binding request", 
            example = "1289358704")
    private String individualId;
    
    @NotEmpty(message = "Challenge list cannot be empty")
    @Valid
    @Schema(description = "List of Challenges for wallet binding", 
            example = "[]")
    private List<IdpChallangeDto> challengeList;
    
    @NotBlank(message = "Public key is required and cannot be blank")
    @Schema(description = "Public key in JWK format", 
            example = "{\"kty\": \"RSA\", \"n\": \"...\", \"e\": \"AQAB\"}")
    private String publicKey;
    
    @Schema(description = "Auth Factory type", 
            allowableValues = {"WLA"},
            example = "WLA")
    private String authFactorType;
    
    @Schema(description = "IDP format", 
            allowableValues = {"jwt"},
            example = "jwt")
    private String format;
}
