package io.mosip.mimoto.dto.resident;

import java.util.ArrayList;
import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import io.mosip.mimoto.dto.ErrorDTO;
import lombok.Data;

@Data
@Schema(description = "Resident service response returned after submitting a credential issuance request.")
public class CredentialRequestResponseDTO {
    @Schema(description = "Response identifier returned by the resident service.")
    private String id;

    @Schema(description = "Version of the resident service response contract.")
    private String version;

    @Schema(description = "Legacy or reserved response field returned by the upstream service.")
    String str;

    @Schema(description = "Timestamp at which the resident service generated the response, in ISO 8601 format.")
    private String responsetime;

    @Schema(description = "Optional metadata returned along with the credential request response.")
    private Object metadata;
    @NotNull
    @Valid
    @Schema(description = "Inner response payload containing the created credential request identifiers.")
    private CredentialRequestResponseInnerResponseDTO response;

    @Schema(description = "List of errors returned by the resident service when the credential request could not be completed.")
    private List<ErrorDTO> errors = new ArrayList<>();

    public CredentialRequestResponseInnerResponseDTO getResponse() {
        return response;
    }

    public List<ErrorDTO> getErrors() {
        return errors;
    }
}
