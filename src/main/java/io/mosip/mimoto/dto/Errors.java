package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
@Schema(description = "Error entry containing a machine-readable code and human-readable message.")
public class Errors {
    @Schema(description = "Machine-readable error code.",
            example = "invalid_request")
    String errorCode;
    @Schema(description = "Human-readable error message.",
            example = "Request payload is invalid")
    String message;
}
