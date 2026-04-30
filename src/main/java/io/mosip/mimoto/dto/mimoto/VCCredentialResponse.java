package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Credential response returned by an issuer, containing the issued credential and its format.")
public class VCCredentialResponse implements Serializable {

    @NotBlank
    @Schema(description = "Format of the issued credential.",
            example = "vc+sd-jwt")
    private String format;

    @Valid
    @NotNull
    @Schema(description = "Issued credential payload in issuer-specific serialized form.")
    private Object credential;

    public String getFormat() {
        return format;
    }

    public Object getCredential() {
        return credential;
    }
}
