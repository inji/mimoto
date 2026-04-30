package io.mosip.mimoto.dto;

import com.google.gson.annotations.Expose;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.URL;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Background image configuration containing the URI of the image asset.")
public class BackgroundImageDTO {
    @Expose
    @URL
    @NotBlank
    @Schema(description = "URI of the background image asset.")
    String uri;

    public String getUri() {
        return uri;
    }
}
