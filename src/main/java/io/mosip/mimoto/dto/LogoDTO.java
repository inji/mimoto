package io.mosip.mimoto.dto;


import com.fasterxml.jackson.annotation.JsonAlias;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.URL;

@Data
public class LogoDTO {
    @Expose
    @NotBlank
    @URL
    @JsonAlias("uri")
    @SerializedName(value = "url", alternate = {"uri"})
    @Schema(description = "Display logo uri of the Issuer")
    String url;
    @Expose
    @NotBlank
    @Schema(description = "Display logo alt text of the Issuer")
    String alt_text;

    public String getUrl() {
        return url;
    }
}
