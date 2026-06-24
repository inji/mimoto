package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
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

    @JsonProperty("claims")
    @Schema(description = "Claims that are always disclosed as part of the credential")
    private List<String> claims;

    @JsonProperty("sdClaims")
    @Schema(description = "Selective Disclosure Claims that require user consent to be shared")
    private List<String> sdClaims;
}

