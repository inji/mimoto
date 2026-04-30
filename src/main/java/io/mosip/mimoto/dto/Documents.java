package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * The Class Documents.
 *
 * @author M1048358 Alok
 */

/**
 * Instantiates a new documents.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Document entry associated with an identity response.")
public class Documents {

    /** The doc type. */
    @Schema(description = "Category or type of the document.")
    private String category;

    /** The doc value. */
    @Schema(description = "Value or identifier of the document.")
    private String value;
}
