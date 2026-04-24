package io.mosip.mimoto.dto;

import io.mosip.mimoto.model.QRCodeType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import org.hibernate.validator.constraints.URL;
import java.util.List;


@Data
public class IssuerDTO {
    @NotBlank
    @Schema(description = "Unique Identifier of the Issuer")
    String issuer_id;

    @NotBlank
    @Schema(description = "protocol of the download flow", allowableValues = {"OTP", "OpenId4VCI"})
    String protocol;

    @Valid
    @NotEmpty
    @Schema(description = "Display Properties of the Issuer")
    List<DisplayDTO> display;

    @NotBlank
    @Schema(description = "Client Id of the Onboarded Mimoto OIDC Client")
    String client_id;

    @URL
    @Schema(description = "Wellknown endpoint of the credential issuer")
    String wellknown_endpoint;

    @Schema(description = "Redirect URI configured while creating the OIDC Client")
    String redirect_uri;

    @Schema(description = "Authorization Audience for retrieving Token from token endpoint")
    String authorization_audience;

    @URL
    @NotBlank
    @Schema(description = "Mimoto Token Endpoint Fetching the Token From Authorization Server with Client Assertion")
    String token_endpoint;

    @URL
    @Schema(description = "Token Endpoint for Fetching the Token From Authorization Server")
    String proxy_token_endpoint;

    @NotBlank
    @Schema(description = "Client Alias of the Issuer in the keyStore file")
    String client_alias;

    @Schema(description = "QR code type of issuer is used to decide whether the downloaded Verifiable Credential is allowed for online sharing or not")
    QRCodeType qr_code_type;

    @NotBlank
    @Schema(description = "Toggle to Enable / Disable the Issuer", defaultValue = "false")
    String enabled;

    @Schema(description = "Unique Identifier of the Issuer")
    String credential_issuer;

    @URL
    @NotBlank
    @Schema(description = "Credential Issuer Host")
    String credential_issuer_host;


    public IssuerDTO mapFromIssuerV2DTO(IssuerV2DTO issuerV2DTO) {
        this.issuer_id = issuerV2DTO.getIssuerId();
        this.protocol = issuerV2DTO.getProtocol();
        this.display = issuerV2DTO.getDisplay();
        this.client_id = issuerV2DTO.getClientId();
        this.client_alias = issuerV2DTO.getClientAlias();
        this.token_endpoint = issuerV2DTO.getTokenEndpoint();
        this.qr_code_type = issuerV2DTO.getQrCodeType();
        this.enabled = issuerV2DTO.getEnabled();
        this.credential_issuer_host = issuerV2DTO.getCredentialIssuerHost();

        return this;
    }
}
