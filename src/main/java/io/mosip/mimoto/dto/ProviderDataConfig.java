package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * The ProviderDataConfig class represents a configuration for provider data attributes.
 * It contains fields for various attributes such as username, name, email, picture, and phone number.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Mapping configuration for identity provider user profile attributes.")
public class ProviderDataConfig {
    @Schema(description = "Attribute name used to read the provider-specific username or subject.")
    private String userNameAttribute;
    @Schema(description = "Attribute name used to read the display name from the provider profile.")
    private String nameAttribute;
    @Schema(description = "Attribute name used to read the email from the provider profile.")
    private String emailAttribute;
    @Schema(description = "Attribute name used to read the picture URL from the provider profile.")
    private String pictureAttribute;
    @Schema(description = "Attribute name used to read the phone number from the provider profile.")
    private String phoneNumberAttribute;
}
