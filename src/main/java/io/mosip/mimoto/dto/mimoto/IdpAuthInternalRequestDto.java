package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Internal IDP authentication request containing transaction and challenge details.")
public class IdpAuthInternalRequestDto {
    
    @NotBlank(message = "Linked transaction ID is required and cannot be blank")
    @Schema(description = "Linked transaction identifier", 
            example = "txn-12345-67890")
    private String linkedTransactionId;
    
    @NotBlank(message = "Individual ID is required and cannot be blank")
    @Schema(description = "Individual identifier (UIN or VID)", 
            example = "1289358704")
    private String individualId;
    
    @NotEmpty(message = "Challenge list cannot be empty")
    @Valid
    @Schema(description = "List of authentication challenges", 
            example = "[]")
    private List<IdpAuthChallangeDto> challengeList;
}
