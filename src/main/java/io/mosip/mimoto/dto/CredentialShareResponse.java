package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
@Schema(description = "Response returned by credential share APIs, including either the response payload or a list of errors.")
public class CredentialShareResponse extends BaseRestResponseDTO {

    private static final long serialVersionUID = 1L;

    @Schema(description = "List of errors returned when credential sharing could not be completed.")
    private List<ErrorDTO> errors;

    @Schema(description = "Successful credential share response payload.")
    private ResponseDTO response;
}
