package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.CredentialMetadata;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.model.VerifiableCredential;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.service.CredentialPDFGeneratorService;
import io.mosip.mimoto.service.CredentialService;
import io.mosip.mimoto.service.CredentialVerifierService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.DataProtectionService;
import io.mosip.mimoto.service.VCDownloadHandler;
import io.mosip.mimoto.service.VCDownloadHandlerFactory;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.util.UUID;

import static io.mosip.mimoto.exception.ErrorConstants.*;

@Slf4j
@Service
public class CredentialServiceImpl implements CredentialService {

    private final ObjectMapper objectMapper;
    private final DataProtectionService dataProtectionService;
    private final WalletCredentialsRepository walletCredentialsRepository;
    private final IssuersService issuersService;
    private final CredentialVerifierService credentialVerifierService;
    private final CredentialPDFGeneratorService credentialPDFGeneratorService;
    private final DataShareServiceImpl dataShareService;
    private final VCDownloadHandlerFactory vcDownloadHandlerFactory;

    @Autowired
    public CredentialServiceImpl(
            ObjectMapper objectMapper,
            DataProtectionService dataProtectionService,
            WalletCredentialsRepository walletCredentialsRepository,
            IssuersService issuersService,
            CredentialVerifierService credentialVerifierService,
            CredentialPDFGeneratorService credentialPDFGeneratorService,
            DataShareServiceImpl dataShareService,
            VCDownloadHandlerFactory vcDownloadHandlerFactory) {

        this.objectMapper = objectMapper;
        this.dataProtectionService = dataProtectionService;
        this.walletCredentialsRepository = walletCredentialsRepository;
        this.issuersService = issuersService;
        this.credentialVerifierService = credentialVerifierService;
        this.credentialPDFGeneratorService = credentialPDFGeneratorService;
        this.dataShareService = dataShareService;
        this.vcDownloadHandlerFactory = vcDownloadHandlerFactory;
    }


    @Override
    public ByteArrayInputStream downloadCredentialAsPDF(String issuerId, String credentialConfigurationId, TokenResponseDTO tokenResponse, String credentialValidity, String locale) throws Exception {
        IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
        CredentialIssuerConfiguration credentialIssuerConfiguration = issuersService.getIssuerConfiguration(issuerId);
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = new CredentialIssuerWellKnownResponse(
                credentialIssuerConfiguration.getCredentialIssuer(),
                credentialIssuerConfiguration.getAuthorizationServers(),
                credentialIssuerConfiguration.getCredentialEndPoint(),
                credentialIssuerConfiguration.getCredentialConfigurationsSupported());
        CredentialsSupportedResponse credentialsSupportedResponse = credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported().get(credentialConfigurationId);

        // TODO: Replace hardcoded "draft13" with dynamic version
        VCDownloadHandler processor = vcDownloadHandlerFactory.getHandler("draft13");
        VCCredentialResponse vcCredentialResponse = processor.downloadCredential(issuerDTO, credentialConfigurationId, credentialIssuerWellKnownResponse, tokenResponse, null, null, false);

        boolean verificationStatus = verifyCredential(vcCredentialResponse, issuerId, credentialConfigurationId);
        if (verificationStatus) {
            String dataShareUrl = QRCodeType.OnlineSharing.equals(issuerDTO.getQr_code_type()) ? dataShareService.storeDataInDataShare(objectMapper.writeValueAsString(vcCredentialResponse), credentialValidity) : "";
            return credentialPDFGeneratorService.generatePdfForVerifiableCredential(credentialConfigurationId, vcCredentialResponse, issuerDTO, credentialsSupportedResponse, dataShareUrl, credentialValidity, locale);
        }
       throw new VCVerificationException(SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(), SIGNATURE_VERIFICATION_EXCEPTION.getErrorMessage());
    }

    /**
     * Download credential and stores a credential using the provided token and parameters.
     *
     * @param tokenResponse             The token response containing the access token.
     * @param credentialConfigurationId The type of the credential.
     * @param walletId                  The ID of the wallet.
     * @param base64Key                 The Base64-encoded wallet key.
     * @param issuerId                  The ID of the issuer.
     * @param locale                    The locale for the response.
     * @return The stored VerifiableCredential response.
     * @throws InvalidRequestException             If input parameters are invalid.
     * @throws CredentialProcessingException       If processing fails.
     * @throws ExternalServiceUnavailableException If an external service is unavailable.
     * @throws VCVerificationException             If credential verification fails.
     * @throws InvalidCredentialResourceException  If the credential resource is invalid.
     */
    public VerifiableCredentialResponseDTO downloadCredentialAndStoreInDB(
            TokenResponseDTO tokenResponse, String credentialConfigurationId, String walletId,
            String base64Key, String issuerId, String locale)
            throws InvalidRequestException, CredentialProcessingException, ExternalServiceUnavailableException, VCVerificationException, InvalidCredentialResourceException {

        // Validate inputs
        validateInputs(tokenResponse, credentialConfigurationId, walletId, base64Key, issuerId);

        // Fetch issuer configuration
        IssuerConfig issuerConfig = fetchIssuerConfig(issuerId, credentialConfigurationId);

        // Download credential from issuer
        // TODO: Replace hardcoded "draft13" with dynamic version 
        VCDownloadHandler processor = vcDownloadHandlerFactory.getHandler("draft13");
        VCCredentialResponse vcCredentialResponse = processor.downloadCredential(issuerConfig.getIssuerDTO(), credentialConfigurationId, issuerConfig.getWellKnownResponse(), tokenResponse, walletId, base64Key, true);

        // Verify credential
        boolean verificationStatus = verifyCredential(vcCredentialResponse, issuerId, credentialConfigurationId);
        if (!verificationStatus) {
            log.error("Signature verification failed for issuerId: {}, credentialConfigurationId: {}", issuerId, credentialConfigurationId);
            throw new VCVerificationException(
                    SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(),
                    SIGNATURE_VERIFICATION_EXCEPTION.getErrorMessage());
        }

        // Serialize, encrypt and store credential
        String encryptedCredentialData = processAndEncryptCredential(vcCredentialResponse, base64Key, issuerId, credentialConfigurationId);
        VerifiableCredential savedCredential = saveCredential(walletId, encryptedCredentialData, issuerId, credentialConfigurationId);

        return VerifiableCredentialResponseDTO.fromIssuerConfig(issuerConfig, locale, savedCredential.getId());
    }

    /**
     * Validates input parameters for credential download.
     */
    private void validateInputs(TokenResponseDTO tokenResponse, String credentialConfigurationId,
                                String walletId, String base64Key, String issuerId) throws InvalidRequestException {
        if (tokenResponse == null || StringUtils.isBlank(tokenResponse.getAccess_token())) {
            log.error("Invalid token response: null or missing access token");
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Token response or access token cannot be null");
        }
        if (StringUtils.isBlank(credentialConfigurationId)) {
            log.error("Invalid credential type: null or blank");
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Credential configuration id cannot be null or blank");
        }
        if (StringUtils.isBlank(walletId)) {
            log.error("Invalid wallet ID: null or blank");
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Wallet ID cannot be null or blank");
        }
        if (StringUtils.isBlank(base64Key)) {
            log.error("Invalid wallet key: null or blank");
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Wallet key cannot be null or blank");
        }
        if (StringUtils.isBlank(issuerId)) {
            log.error("Invalid issuer ID: null or blank");
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Issuer ID cannot be null or blank");
        }
    }

    /**
     * Fetches issuer configuration.
     */
    private IssuerConfig fetchIssuerConfig(String issuerId, String credentialConfigurationId) throws CredentialProcessingException {
        try {
            return issuersService.getIssuerConfig(issuerId, credentialConfigurationId);
        } catch (Exception e) {
            log.error("Failed to fetch issuer config for issuerId: {}", issuerId, e);
            throw new CredentialProcessingException(
                    CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(),
                    "Unable to fetch issuer configuration", e);
        }
    }

    /**
     * Verifies credential signature.
     */
    private boolean verifyCredential(VCCredentialResponse vcCredentialResponse, String issuerId, String credentialConfigurationId)
            throws VCVerificationException {
        try {
            return credentialVerifierService.verify(vcCredentialResponse);
        } catch (VCVerificationException | JsonProcessingException e) {
            log.error("Credential verification failed for issuerId: {}, credentialConfigurationId: {}", issuerId, credentialConfigurationId, e);
            throw new VCVerificationException(
                    SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(),
                    "Credential verification failed");
        }
    }

    /**
     * Processes and encrypts credential data.
     */
    private String processAndEncryptCredential(VCCredentialResponse vcCredentialResponse, String base64Key,
                                               String issuerId, String credentialConfigurationId) throws CredentialProcessingException {
        try {
            String vcResponseAsJsonString = objectMapper.writeValueAsString(vcCredentialResponse);
            return dataProtectionService.encryptCredential(vcResponseAsJsonString, base64Key);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize credential response for issuerId: {}, credentialConfigurationId: {}", issuerId, credentialConfigurationId, e);
            throw new CredentialProcessingException(
                    CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(),
                    "Unable to serialize credential response", e);
        } catch (Exception e) {
            log.error("Failed to encrypt credential for issuerId: {}, credentialConfigurationId: {}", issuerId, credentialConfigurationId, e);
            throw new CredentialProcessingException(
                    CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(),
                    "Unable to encrypt credential data", e);
        }
    }

    /**
     * Saves the credential to the repository.
     *
     * @param walletId            The wallet ID.
     * @param encryptedCredential The encrypted credential data.
     * @param issuerId            The issuer ID.
     * @param credentialConfigurationId      The credential configuration id.
     * @return The stored VerifiableCredential.
     */
    private VerifiableCredential saveCredential(String walletId, String encryptedCredential, String issuerId,
                                                String credentialConfigurationId) throws CredentialProcessingException {
        CredentialMetadata credentialMetadata = new CredentialMetadata();
        credentialMetadata.setIssuerId(issuerId);
        credentialMetadata.setCredentialType(credentialConfigurationId);

        VerifiableCredential verifiableCredential = new VerifiableCredential();
        verifiableCredential.setId(UUID.randomUUID().toString());
        verifiableCredential.setWalletId(walletId);
        verifiableCredential.setCredential(encryptedCredential);
        verifiableCredential.setCredentialMetadata(credentialMetadata);

        try {
            return walletCredentialsRepository.save(verifiableCredential);
        } catch (Exception e) {
            log.error("Failed to save credential for walletId: {}, issuerId: {}, credentialConfigurationId: {}", walletId, issuerId, credentialConfigurationId, e);
            throw new CredentialProcessingException(
                    CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(),
                    "Unable to save credential to database", e);
        }
    }
}