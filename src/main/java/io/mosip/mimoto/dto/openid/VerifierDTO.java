package io.mosip.mimoto.dto.openid;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Builder.Default;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerifierDTO {
    @JsonProperty("client_id")
    @Schema(description = "Client Id of the Verifier")
    String clientId;

    @JsonProperty("redirect_uris")
    @Schema(description = "Redirect URIs of the Verifier")
    List<String> redirectUris;

    @JsonProperty("response_uris")
    @Schema(description = "Response URIs of the Verifier")
    List<String> responseUris;

    @JsonProperty("jwks_uri")
    @Schema(description = "JWKS URI of the Verifier")
    @JsonInclude(NON_NULL)
    String jwksUri;

    @JsonProperty("allow_unsigned_request")
    @Schema(description = "Flag to indicate if unsigned Authorization Request is allowed")
    @Default
    Boolean allowUnsignedRequest = false;

    @JsonProperty("spec_version")
    @Schema(description = "OpenID4VP specification version supported by the Verifier")
    @Default
    SpecVersion specVersion = SpecVersion.V1_0;
}

