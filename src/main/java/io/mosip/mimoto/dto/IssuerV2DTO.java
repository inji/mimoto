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
public class IssuerV2DTO {

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

    @NotBlank
    @JsonProperty("client_alias")
    @Schema(description = "Client Alias of the Issuer in the keyStore file")
    private String clientAlias;

    @URL
    @NotBlank
    @JsonProperty("token_endpoint")
    @Schema(description = "Mimoto Token Endpoint Fetching the Token From Authorization Server with Client Assertion")
    private String tokenEndpoint;


    @JsonProperty("qr_code_type")
    @Schema(description = "QR code type of issuer is used to decide whether the downloaded Verifiable Credential is allowed for online sharing or not")
    private QRCodeType qrCodeType;

    @NotBlank
    @Schema(description = "Toggle to Enable / Disable the Issuer", defaultValue = "false")
    private String enabled;

    @URL
    @NotBlank
    @JsonProperty("credential_issuer_host")
    @Schema(description = "Credential Issuer Host")
    private String credentialIssuerHost;

}
