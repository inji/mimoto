package io.mosip.mimoto.dto;

import java.util.Arrays;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
@Schema(description = "Generic token response wrapper returned by upstream authentication services.")
public class TokenResponseDTO {

    @Schema(description = "Response identifier.",
            example = "mosip.identity.token")
    String id;
    @Schema(description = "Version of the response contract.",
            example = "1.0")
    String version;
    @Schema(description = "Timestamp at which the response was generated, in ISO 8601 format.",
            example = "2026-04-27T10:15:31Z")
    String responsetime;
    @Schema(description = "Optional metadata returned with the response.",
            example = "{}")
    String metadata;
    @Schema(description = "Successful response payload.")
    Response response;
    @Schema(description = "Errors returned when the request could not be completed.")
    Errors[] errors;

    public Errors[] getErrors() {
        if (errors != null) {
            return Arrays.copyOf(errors, errors.length);
        } else {
            return null;
        }
    }

    public void setErrors(Errors[] errors) {
        this.errors = errors != null ? errors : null;
    }

}
