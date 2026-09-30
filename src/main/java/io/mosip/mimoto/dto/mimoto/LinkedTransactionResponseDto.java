package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;

@Data
@Schema(description = "Linked transaction response containing the transaction identifier.")
public class LinkedTransactionResponseDto {
    
    @NotBlank(message = "Linked transaction ID is required and cannot be blank")
    @Schema(description = "Linked transaction identifier", 
            example = "txn-12345-67890")
    private String linkedTransactionId;
}