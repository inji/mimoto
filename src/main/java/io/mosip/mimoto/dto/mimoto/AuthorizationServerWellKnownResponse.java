package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import org.hibernate.validator.constraints.URL;
import java.util.List;


@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthorizationServerWellKnownResponse {

    @NotBlank
    @URL
    @SerializedName("authorization_endpoint")
    @JsonProperty("authorization_endpoint")
    @Schema(description = "Endpoint for Authenticating & Authorizing the user")
    private String authorizationEndpoint;


    @NotEmpty
    @SerializedName("grant_types_supported")
    @JsonProperty("grant_types_supported")
    @Schema(description = "List of grant types_supported by Authorization Server")
    private List<@NotBlank String> grantTypesSupported;

    @NotBlank
    @URL
    @SerializedName("token_endpoint")
    @JsonProperty(value = "token_endpoint")
    @Schema(description = "Endpoint for getting the token from the authorization server")
    private String tokenEndpoint;

    @SerializedName("dpop_signing_alg_values_supported")
    @JsonProperty("dpop_signing_alg_values_supported")
    @Schema(description = "JWS algorithms the authorization server accepts for DPoP proofs")
    private List<@NotBlank String> dpopSigningAlgValuesSupported;
}