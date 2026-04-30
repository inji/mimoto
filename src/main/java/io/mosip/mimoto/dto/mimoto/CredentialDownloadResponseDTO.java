package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.databind.JsonNode;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(description = "Response payload returned after a credential download request, containing both the wallet-friendly credential view and the underlying verifiable credential document.")
public class CredentialDownloadResponseDTO {

    @NotNull(message = "Credential is required")
    @Schema(description = "Credential data transformed into the application-specific JSON structure used for wallet display and downstream processing.", 
            example = "{\"credential\": {...}}")
    private JsonNode credential;

    @NotNull(message = "Verifiable credential is required")
    @Schema(description = "Issued verifiable credential document in its standard interoperable format, such as JSON-LD VC.", 
            example = "{\"@context\": [...], \"type\": [...]}")
    private JsonNode verifiableCredential;

    public void setCredential(JsonNode credential) {
        this.credential = credential;
    }

    public void setVerifiableCredential(JsonNode verifiableCredential) {
        this.verifiableCredential = verifiableCredential;
    }
}
