package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.WriterException;
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
import io.mosip.mimoto.service.DPoPSessionService;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.PkceSessionManager;
import io.mosip.mimoto.service.DataProtectionService;
import io.mosip.mimoto.service.VCDownloadHandler;
import io.mosip.mimoto.service.VCDownloadHandlerFactory;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
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
    private final IdpService idpService;
    private final DPoPSessionService dPoPSessionService;
    private final PkceSessionManager pkceSessionManager;

    public CredentialServiceImpl(
            ObjectMapper objectMapper,
            DataProtectionService dataProtectionService,
            WalletCredentialsRepository walletCredentialsRepository,
            IssuersService issuersService,
            CredentialVerifierService credentialVerifierService,
            CredentialPDFGeneratorService credentialPDFGeneratorService,
            DataShareServiceImpl dataShareService,
            VCDownloadHandlerFactory vcDownloadHandlerFactory,
            IdpService idpService,
            DPoPSessionService dPoPSessionService,
            PkceSessionManager pkceSessionManager) {

        this.objectMapper = objectMapper;
        this.dataProtectionService = dataProtectionService;
        this.walletCredentialsRepository = walletCredentialsRepository;
        this.issuersService = issuersService;
        this.credentialVerifierService = credentialVerifierService;
        this.credentialPDFGeneratorService = credentialPDFGeneratorService;
        this.dataShareService = dataShareService;
        this.vcDownloadHandlerFactory = vcDownloadHandlerFactory;
        this.idpService = idpService;
        this.dPoPSessionService = dPoPSessionService;
        this.pkceSessionManager = pkceSessionManager;
    }


    @Override
    public ByteArrayInputStream downloadCredentialAsPDF(String issuerId, String credentialConfigurationId,
                                                         String credentialValidity, String locale, String code,
                                                         String state, HttpSession httpSession)
            throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException,
            ExternalServiceUnavailableException, WriterException, AuthorizationServerWellknownResponseException,
            IssuerOnboardingException {
        TokenResponseDTO tokenResponse = exchangeToken(httpSession, state, code, issuerId);
        IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse =
                issuersService.getIssuerWellKnownResponse(issuerDTO.getCredential_issuer_host());
        String credentialEndpoint = credentialIssuerWellKnownResponse.getCredentialEndPoint();
        String proof = dPoPSessionService.credentialProof(httpSession, state, tokenResponse, credentialEndpoint);
        try {
            return generateCredentialPdf(issuerDTO, credentialIssuerWellKnownResponse, credentialConfigurationId,
                    tokenResponse, credentialValidity, locale, proof);
        } catch (DPoPChallengeException exception) {
            log.info("Retrying guest credential download after DPoP nonce challenge for issuer: {}", issuerId);
            String retryProof = dPoPSessionService.retryCredentialProof(
                    httpSession, state, tokenResponse, exception.getNonce(), credentialEndpoint);
            return generateCredentialPdf(issuerDTO, credentialIssuerWellKnownResponse, credentialConfigurationId,
                    tokenResponse, credentialValidity, locale, retryProof);
        }
    }

    private TokenResponseDTO exchangeToken(HttpSession httpSession, String state, String code, String issuerId)
            throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException,
            InvalidWellknownResponseException, IssuerOnboardingException {
        if (StringUtils.isBlank(state)) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "DPoP state is required");
        }
        if (dPoPSessionService.find(httpSession, state) != null) {
            TokenResponseDTO exchanged = idpService.exchangeAndBindToken(
                    pkceSessionManager.authorizationCodeParams(httpSession, state, code, issuerId),
                    httpSession);
            if (exchanged != null) {
                return exchanged;
            }
        }
        throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                "DPoP session not found or token is not bound");
    }

    private ByteArrayInputStream generateCredentialPdf(IssuerDTO issuerDTO,
                                                       CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse,
                                                       String credentialConfigurationId, TokenResponseDTO tokenResponse,
                                                       String credentialValidity, String locale, String dPoPProof)
            throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException,
            ExternalServiceUnavailableException, WriterException {
        CredentialsSupportedResponse credentialsSupportedResponse = credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported().get(credentialConfigurationId);

        VCDownloadHandler processor = vcDownloadHandlerFactory.getHandler(credentialIssuerWellKnownResponse.getVersion());
        VCCredentialResponse vcCredentialResponse = processor.downloadCredential(issuerDTO, credentialConfigurationId, credentialIssuerWellKnownResponse, tokenResponse, null, null, false, dPoPProof);

        boolean verificationStatus = verifyCredential(vcCredentialResponse, issuerDTO.getIssuer_id(), credentialConfigurationId);
        if (verificationStatus) {
            String dataShareUrl = QRCodeType.OnlineSharing.equals(issuerDTO.getQr_code_type()) ? dataShareService.storeDataInDataShare(objectMapper.writeValueAsString(vcCredentialResponse), credentialValidity) : "";
            return credentialPDFGeneratorService.generatePdfForVerifiableCredential(credentialConfigurationId, vcCredentialResponse, issuerDTO, credentialsSupportedResponse, dataShareUrl, credentialValidity, locale);
        }
       throw new VCVerificationException(SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(), SIGNATURE_VERIFICATION_EXCEPTION.getErrorMessage());
    }

    @Override
    public VerifiableCredentialResponseDTO downloadCredentialAndStoreInDB(
            String issuerId, String credentialConfigurationId, String walletId, String base64Key,
            String locale, String code, String state, HttpSession httpSession)
            throws InvalidRequestException, CredentialProcessingException, ExternalServiceUnavailableException,
            VCVerificationException, InvalidCredentialResourceException, ApiNotAccessibleException, IOException,
            AuthorizationServerWellknownResponseException, InvalidWellknownResponseException, IssuerOnboardingException {
        TokenResponseDTO tokenResponse = exchangeToken(httpSession, state, code, issuerId);
        validateInputs(tokenResponse, credentialConfigurationId, walletId, base64Key, issuerId);
        IssuerConfig issuerConfig = fetchIssuerConfig(issuerId, credentialConfigurationId);
        String credentialEndpoint = issuerConfig.getWellKnownResponse().getCredentialEndPoint();
        String proof = dPoPSessionService.credentialProof(httpSession, state, tokenResponse, credentialEndpoint);
        log.info("Credential DPoP proof for issuer {} endpoint {}: {}",
                issuerId, credentialEndpoint, StringUtils.isNotBlank(proof) ? "present" : "absent");
        try {
            return storeDownloadedCredential(tokenResponse, credentialConfigurationId, walletId, base64Key, issuerId, locale, proof, issuerConfig);
        } catch (DPoPChallengeException exception) {
            log.info("Retrying wallet credential download after DPoP nonce challenge for issuer: {}", issuerId);
            String retryProof = dPoPSessionService.retryCredentialProof(
                    httpSession, state, tokenResponse, exception.getNonce(), credentialEndpoint);
            return storeDownloadedCredential(tokenResponse, credentialConfigurationId, walletId, base64Key, issuerId, locale, retryProof, issuerConfig);
        }
    }

    private VerifiableCredentialResponseDTO storeDownloadedCredential(
            TokenResponseDTO tokenResponse, String credentialConfigurationId, String walletId,
            String base64Key, String issuerId, String locale, String dPoPProof, IssuerConfig issuerConfig)
            throws InvalidRequestException, CredentialProcessingException, ExternalServiceUnavailableException,
            VCVerificationException, InvalidCredentialResourceException {

        VCDownloadHandler processor = vcDownloadHandlerFactory.getHandler(issuerConfig.getWellKnownResponse().getVersion());
        VCCredentialResponse vcCredentialResponse = processor.downloadCredential(issuerConfig.getIssuerDTO(), credentialConfigurationId, issuerConfig.getWellKnownResponse(), tokenResponse, walletId, base64Key, true, dPoPProof);

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