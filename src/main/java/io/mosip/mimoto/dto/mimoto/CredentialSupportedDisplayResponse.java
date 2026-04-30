package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import io.mosip.mimoto.dto.BackgroundImageDTO;
import io.mosip.mimoto.dto.LogoDTO;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.Map;

@Data
public class CredentialSupportedDisplayResponse {

    @Expose
    @NotBlank
    @Schema(description = "Name of the Supported Credential")
    String name;

    @Expose
    @NotBlank
    @Schema(description = "Locale of the Supported Credential")
    String locale;

    @Expose
    @NotNull
    @Valid
    @Schema(description = "Logo of the Supported Credential")
    LogoDTO logo;

    @JsonProperty("background_image")
    @SerializedName("background_image")
    @Expose
    @Valid
    @Schema(description = "Background Image  of the Supported Credential")
    BackgroundImageDTO backgroundImage;

    @JsonProperty("background_color")
    @SerializedName("background_color")
    @Expose
    @NotBlank
    @Schema(description = "Background Colour of the Supported Credential")
    String backgroundColor;

    @JsonProperty("text_color")
    @SerializedName("text_color")
    @Expose
    @NotBlank
    @Schema(description = "Text Colour of the Supported Credential")
    String textColor;

    public String getName() {
        return name;
    }

    public String getLocale() {
        return locale;
    }

    public BackgroundImageDTO getBackgroundImage() {
        return backgroundImage;
    }

    public String getBackgroundColor() {
        return backgroundColor;
    }

    public String getTextColor() {
        return textColor;
    }
}
