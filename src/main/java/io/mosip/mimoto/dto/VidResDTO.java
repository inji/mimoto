package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.io.Serializable;

/**
 * This class will provide values to hold uin,vid and vidStatus
 * 
 * @author Prem Kumar
 *
 */
@Data
@Schema(description = "Virtual ID response payload containing UIN, VID, and status information.")
public class VidResDTO implements Serializable {

    /** The Value Of UIN in Decrypted value */
    @JsonProperty("UIN")
    @Schema(description = "UIN associated with the returned virtual ID.")
    private String uin;

    /** The Value to hold vid */
    @JsonProperty("VID")
    @Schema(description = "Virtual ID returned by the service.")
    private String vid;

    /** The Value to hold vidStatus */
    @Schema(description = "Status of the returned virtual ID.")
    private String vidStatus;

    /** The Value to hold updatedVid */
    @Schema(description = "Nested virtual ID details representing a restored or updated VID.")
    private VidResDTO restoredVid;

}
