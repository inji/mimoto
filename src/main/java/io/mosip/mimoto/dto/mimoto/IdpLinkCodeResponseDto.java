package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;

@Data
@Schema(description = "IDP link code response containing transaction and expiration details.")
public class IdpLinkCodeResponseDto {
    
    @NotBlank(message = "Transaction ID is required and cannot be blank")
    @Schema(description = "Transaction identifier", 
            example = "txn-12345-67890")
    private String transactionId;
    
    @NotBlank(message = "Link code is required and cannot be blank")
    @Schema(description = "Link code for transaction linking", 
            example = "LINK123456")
    private String linkCode;
    
    @NotBlank(message = "Expiration time is required and cannot be blank")
    @Schema(description = "Link code expiration timestamp in ISO 8601 format", 
            example = "2026-04-08T12:30:00Z")
    private String expireDateTime;
}
