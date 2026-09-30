package io.mosip.mimoto.dto.resident;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Resident service response describing the current status of a credential issuance request.")
public class CredentialRequestStatusResponseDTO {
    @Schema(description = "Identifier of the credential request status response.")
    private String id;

    @Schema(description = "Credential request identifier whose status is being reported.")
    private String requestId;

    @Schema(description = "Current status code of the credential issuance workflow.",
            example = "ISSUED")
    private String statusCode;
}
