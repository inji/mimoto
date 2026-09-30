package io.mosip.mimoto.dto;

import java.io.Serializable;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * Instantiates a new base request response DTO.
 * 
 * @author Rishabh Keshari
 */
@Data
@Schema(description = "Base request DTO containing standard request metadata shared across REST APIs.")
public class BaseRestRequestDTO implements Serializable {

    private static final long serialVersionUID = 4373201325809902206L;

    /** The id. */
    @Schema(description = "Request identifier used to categorize or trace the API invocation.",
            example = "io.mosip.resident.otp")
    private String id;

    /** The ver. */
    @Schema(description = "Version of the API or request contract.",
            example = "v1")
    private String version;

    /** The timestamp. */
    @Schema(description = "Timestamp at which the request was created, in ISO 8601 format.",
            example = "2026-04-24T12:00:00Z")
    private String requesttime;

}
