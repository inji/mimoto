package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * Instantiates a new json value.
 */
@Data
@Schema(description = "Localized text entry containing a language tag and value.")
public class JsonValue {

    /** The language. */
    @Schema(description = "Language code associated with the value.",
            example = "en")
    private String language;

    /** The value. */
    @Schema(description = "Localized value for the specified language.")
    private String value;

    public String getLanguage() {
        return language;
    }
}
