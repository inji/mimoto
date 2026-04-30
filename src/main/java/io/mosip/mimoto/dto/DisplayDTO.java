package io.mosip.mimoto.dto;

import com.google.gson.annotations.Expose;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

@Data
public class DisplayDTO {
    @Expose
    @NotBlank
    @Schema(description = "Display Name of the Issuer")
    String name;
    @Expose
    @Valid
    @Schema(description = "Display Logo of the Issuer")
    LogoDTO logo;
    @Expose
    @NotBlank
    @Schema(description = "Display title of the Issuer")
    String title;
    @Expose
    @NotBlank
    @Schema(description = "Display description of the Issuer")
    String description;
    @Expose
    @NotBlank
    @Schema(description = "Display language of the Issuer")
    String language;

    public LogoDTO getLogo() {
        return logo;
    }
}
