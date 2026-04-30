package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;

@Data
@Schema(description = "Credential download request payload for retrieving a verifiable credential.")
public class CredentialDownloadRequestDTO {
    
    @NotBlank(message = "Individual ID is required and cannot be blank")
    @Schema(description = "Unique individual identifier (UIN or VID)", 
            example = "1289358704")
    private String individualId;
    
    @NotBlank(message = "Request ID is required and cannot be blank")
    @Schema(description = "Unique request identifier for the credential download", 
            example = "req-12345-67890")
    private String requestId;

    public String getIndividualId() {
        return individualId;
    }

    public String getRequestId() {
        return requestId;
    }
}
