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
@Schema(description = "Base response DTO containing standard metadata returned by REST APIs.")
public class BaseRestResponseDTO implements Serializable {

    private static final long serialVersionUID = 4246582347420843195L;

    /** The id. */
    @Schema(description = "Response identifier associated with the processed API operation.",
            example = "io.mosip.resident.otp")
    private String id;

    /** The ver. */
    @Schema(description = "Version of the API or response contract.",
            example = "v1")
    private String version;

    /** The timestamp. */
    @Schema(description = "Timestamp at which the response was generated, in ISO 8601 format.",
            example = "2026-04-24T12:00:01Z")
    private String responsetime;

}
