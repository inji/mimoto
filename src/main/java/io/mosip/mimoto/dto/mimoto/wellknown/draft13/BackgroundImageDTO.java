package io.mosip.mimoto.dto.mimoto.wellknown.draft13;

import com.google.gson.annotations.Expose;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.URL;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class BackgroundImageDTO {
    @Expose
    @URL
    @NotBlank
    String uri;
}
