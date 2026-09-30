package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;

@Data
@Schema(description = "IDP authentication request containing credentials and challenge responses.")
public class IdpAuthenticateRequestDto {
    
    @NotBlank(message = "Request time is required and cannot be blank")
    @Schema(description = "Request timestamp in ISO 8601 format", 
            example = "2026-04-08T12:00:00Z")
    private String requesttime;
    
    @NotBlank(message = "Link transaction ID is required and cannot be blank")
    @Schema(description = "Link transaction identifier", 
            example = "txn-12345-67890")
    private String linkTransactionId;
    
    @NotBlank(message = "Individual ID is required and cannot be blank")
    @Schema(description = "Individual identifier (UIN or VID)", 
            example = "1289358704")
    private String individualId;
    
    @NotEmpty(message = "Challenge list cannot be empty")
    @Valid
    @Schema(description = "List of challenge responses", 
            example = "[]")
    private List<IdpChallangeDto> challengeList;
}
