package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.mimoto.model.QRCodeType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import org.hibernate.validator.constraints.URL;

import java.util.List;

@Data
public class IssuerResponseDTO {

    @NotBlank
    @Schema(description = "Unique Identifier of the Issuer")
    @JsonProperty("issuer_id")
    private String issuerId;

    @NotBlank
    @Schema(description = "protocol of the download flow", allowableValues = {"OTP", "OpenId4VCI"})
    private String protocol;

    @Valid
    @NotEmpty
    @Schema(description = "Display Properties of the Issuer")
    private List<DisplayDTO> display;

    @NotBlank
    @Schema(description = "Client Id of the Onboarded Mimoto OIDC Client")
    @JsonProperty("client_id")
    private String clientId;

    @URL
    @NotBlank
    @Schema(description = "Wellknown endpoint of the credential issuer")
    @JsonProperty("wellknown_endpoint")
    private String wellknownEndpoint;

    @NotBlank
    @Schema(description = "Redirect URI configured while creating the OIDC Client")
    @JsonProperty("redirect_uri")
    String redirectUri;

    @Schema(description = "Authorization Audience for retrieving Token from token endpoint")
    @JsonProperty("authorization_audience")
    String authorizationAudience;

    @URL
    @NotBlank
    @JsonProperty("token_endpoint")
    @Schema(description = "Mimoto Token Endpoint Fetching the Token From Authorization Server with Client Assertion")
    String tokenEndpoint;

    @URL
    @JsonProperty("proxy_token_endpoint")
    @Schema(description = "Token Endpoint for Fetching the Token From Authorization Server")
    String proxyTokenEndpoint;

    @NotBlank
    @JsonProperty("client_alias")
    @Schema(description = "Client Alias of the Issuer in the keyStore file")
    String clientAlias;

    @JsonProperty("qr_code_type")
    @Schema(description = "QR code type of issuer is used to decide whether the downloaded Verifiable Credential is allowed for online sharing or not")
    QRCodeType qrCodeType;

    @NotBlank
    @Schema(description = "Toggle to Enable / Disable the Issuer", defaultValue = "false")
    String enabled;

    @JsonProperty("credential_issuer")
    @Schema(description = "Unique Identifier of the Issuer")
    String credentialIssuer;

    @URL
    @NotBlank
    @JsonProperty("credential_issuer_host")
    @Schema(description = "Credential Issuer Host")
    String credentialIssuerHost;

}
