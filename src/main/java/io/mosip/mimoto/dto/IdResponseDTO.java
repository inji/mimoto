package io.mosip.mimoto.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Identity response returned by resident-related APIs.")
public class IdResponseDTO {

    /** The entity. */
    @Schema(description = "Entity type represented by the identity response.")
    private String entity;

    /** The identity. */
    @Schema(description = "Identity payload containing demographic or related data.")
    private Object identity;

    @Schema(description = "List of document entries associated with the identity.")
    private List<Documents> documents;

    /** The status. */
    @Schema(description = "Status of the identity lookup or response generation.")
    private String status;
}
