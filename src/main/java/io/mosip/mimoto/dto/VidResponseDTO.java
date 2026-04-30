package io.mosip.mimoto.dto;

import java.util.List;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Response wrapper returned for virtual ID APIs.")
public class VidResponseDTO extends BaseRestResponseDTO {

    private static final long serialVersionUID = -3604571018699722626L;

    @Schema(description = "Legacy or reserved response field returned by the upstream service.")
    private String str;

    @Schema(description = "Optional metadata returned with the VID response.")
    private String metadata;

    @Schema(description = "Successful virtual ID response payload.")
    private VidResDTO response;

    @Schema(description = "Errors returned when the VID request could not be completed.")
    private List<ErrorDTO> errors;

}
