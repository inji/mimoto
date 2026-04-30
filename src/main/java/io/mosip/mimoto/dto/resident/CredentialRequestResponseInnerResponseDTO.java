package io.mosip.mimoto.dto.resident;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Inner response payload returned after a credential issuance request is accepted.")
public class CredentialRequestResponseInnerResponseDTO {
    @Schema(description = "Identifier of the accepted credential request response record.")
    private String id;

    @Schema(description = "Credential request identifier that can be used later to poll status or download data.")
    private String requestId;

    public String getRequestId() {
        return requestId;
    }
}
