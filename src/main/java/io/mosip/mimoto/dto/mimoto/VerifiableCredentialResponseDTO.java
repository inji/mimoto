package io.mosip.mimoto.dto.mimoto;

import io.mosip.mimoto.dto.DisplayDTO;
import io.mosip.mimoto.dto.IssuerV2DTO;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import static io.mosip.mimoto.util.LocaleUtils.getCredentialDisplayDTOBasedOnLocale;
import static io.mosip.mimoto.util.LocaleUtils.getIssuerDisplayDTOBasedOnLocale;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor

// Holds details related to credential UUID as per stored in DB and other metadata to display in wallet
public class VerifiableCredentialResponseDTO {
    @Schema(description = "Name of the issuer")
    private String issuerDisplayName;

    @Schema(description = "logo of the issuer")
    private String issuerLogo;

    @Schema(description = "Name of the credential type")
    private String credentialTypeDisplayName;

    @Schema(description = "logo of the credential type")
    private String credentialTypeLogo;

    @Schema(description = "Unique Identifier of the Credential in database")
    private String credentialId;

    public static VerifiableCredentialResponseDTO fromIssuerConfig(
            IssuerConfig issuerConfig, String locale, String credentialId) {
        String issuerName = "";
        String issuerLogo = "";
        String credentialType = "";
        String credentialTypeLogo = "";
        DisplayDTO issuerDisplayDTO;
        CredentialSupportedDisplayResponse credentialTypeDisplayDTO;
        if (null != issuerConfig) {
            IssuerV2DTO issuerDTO = issuerConfig.getIssuerDTO();
            CredentialsSupportedResponse credentialsSupportedResponse = issuerConfig.getCredentialsSupportedResponse();
            if (issuerDTO != null) {
                issuerDisplayDTO = getIssuerDisplayDTOBasedOnLocale(issuerDTO.getDisplay(), locale);
                issuerName = issuerDisplayDTO.getName();
                issuerLogo = issuerDisplayDTO.getLogo().getUrl();
            }
            if (credentialsSupportedResponse != null) {
                credentialTypeDisplayDTO = getCredentialDisplayDTOBasedOnLocale(
                        credentialsSupportedResponse.getDisplay(), locale);
                credentialType = credentialTypeDisplayDTO.getName();
                credentialTypeLogo = credentialTypeDisplayDTO.getLogo().getUrl();
            }
        }

        return VerifiableCredentialResponseDTO.builder()
                .issuerDisplayName(issuerName)
                .issuerLogo(issuerLogo)
                .credentialTypeDisplayName(credentialType)
                .credentialTypeLogo(credentialTypeLogo)
                .credentialId(credentialId)
                .build();
    }
}