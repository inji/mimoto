package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Class for Audit Response having status of audit.
 *
 * @author Dharmesh Khandelwal
 * @since 1.0.0
 */

/*
 * (non-Javadoc)
 * 
 * @see java.lang.Object#toString()
 */
@Data

/**
 * Instantiates a new audit response dto.
 */
@NoArgsConstructor

/**
 * Instantiates a new audit response dto.
 *
 * @param status the status
 */
@AllArgsConstructor
@Schema(description = "Audit service response indicating whether the audit entry was recorded successfully.")
public class AuditResponseDto {

    /** The boolean audit status. */
    @Schema(description = "Flag indicating whether the audit request was processed successfully.")
    private boolean status;

}
