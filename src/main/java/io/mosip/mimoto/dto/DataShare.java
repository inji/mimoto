package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.io.Serializable;

/**
 * Instantiates a new data share.
 */

/**
 * Instantiates a new data share.
 */
@Data
@Schema(description = "Data share descriptor containing the URL and limits for accessing shared data.")
public class DataShare implements Serializable {

    /** The url. */
    @Schema(description = "URL from which the shared data can be retrieved.")
    private String url;

    /** The valid for in minutes. */
    @Schema(description = "Validity period of the data share link, in minutes.")
    private int validForInMinutes;

    /** The transactions allowed. */
    @Schema(description = "Maximum number of times the data share can be used.")
    private int transactionsAllowed;

    /** The policy id. */
    @Schema(description = "Policy identifier associated with the data share.")
    private String policyId;

    /** The subscriber id. */
    @Schema(description = "Subscriber identifier associated with the data share.")
    private String subscriberId;

    /** The signature. */
    @Schema(description = "Signature protecting the integrity of the data share metadata.")
    private String signature;

}
