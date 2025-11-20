package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialDTO {

    @JsonProperty("credentialId")
    @Schema(description = "Unique identifier of the credential")
    private String credentialId;

    @JsonProperty("credentialTypeDisplayName")
    @Schema(description = "Display name of the credential type")
    private String credentialTypeDisplayName;

    @JsonProperty("credentialTypeLogo")
    @Schema(description = "Logo URL for the credential type")
    private String credentialTypeLogo;

    @JsonProperty("format")
    @Schema(description = "Format of the credential (e.g., ldp_vc, vc+sd-jwt, dc+sd-jwt)")
    private String format;
}

