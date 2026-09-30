package io.mosip.mimoto.core.http;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(description = "Generic API request wrapper containing request metadata and the actual request payload.")
public class RequestWrapper<T> {
    @Schema(description = "Request identifier used by upstream systems to categorize or trace the API call.",
            example = "mosip.resident.vid")
    private String id;

    @Schema(description = "API version associated with the wrapped request payload.",
            example = "v1")
    private String version;

    @Schema(description = "Timestamp at which the request wrapper was created, in ISO 8601 format.",
            example = "2026-04-24T12:00:00Z")
    private String requesttime;

    @Schema(description = "Optional metadata map containing additional request context.")
    private Object metadata;

    @NotNull
    @Valid
    @Schema(description = "Actual business request payload carried inside the wrapper.")
    private T request;

}
