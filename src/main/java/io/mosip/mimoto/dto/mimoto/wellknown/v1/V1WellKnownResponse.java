package io.mosip.mimoto.dto.mimoto.wellknown.v1;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import org.hibernate.validator.constraints.URL;

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class V1WellKnownResponse {
    @NotBlank
    @URL
    @SerializedName("credential_issuer")
    @JsonProperty("credential_issuer")
    @Schema(description = "Unique Identifier of the Credential Issuer")
    private String credentialIssuer;

    @NotEmpty
    @SerializedName("authorization_servers")
    @JsonProperty("authorization_servers")
    @Schema(description = "List of Authorization Server Endpoint")
    private List<@NotBlank @URL String> authorizationServers;

    @NotBlank
    @SerializedName("credential_endpoint")
    @Pattern(regexp = "https?://.*?/credential$")
    @JsonProperty("credential_endpoint")
    @Schema(description = "Endpoint to download the Credential")
    private String credentialEndPoint;

    @SerializedName("nonce_endpoint")
    @JsonProperty("nonce_endpoint")
    @Schema(description = "Endpoint to obtain a nonce for credential requests")
    private String nonceEndpoint;

    @NotEmpty
    @Valid
    @SerializedName("credential_configurations_supported")
    @JsonProperty("credential_configurations_supported")
    @Schema(description = "List of Credential Configurations Supported")
    private Map<@NotBlank String, @Valid CredentialsSupportedResponse> credentialConfigurationsSupported;
}
