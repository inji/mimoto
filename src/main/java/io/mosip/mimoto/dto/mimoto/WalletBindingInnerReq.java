package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.util.List;

@Data
public class WalletBindingInnerReq {

    @Schema(description = "Individual Id ")
    private String individualId;
    @Schema(description = "List of Challenges")
    private List<IdpChallangeDto> challengeList;
    @Schema(description = "public key in JWK")
    private String publicKey;
    @Schema(description = "Auth Factory type", allowableValues = {"WLA"})
    private String authFactorType;
    @Schema(description = "IDP format", allowableValues = {"jwt"})
    private String format;
    @Schema(description = "Issuer name requesting binding")
    private String issuerName;
}
