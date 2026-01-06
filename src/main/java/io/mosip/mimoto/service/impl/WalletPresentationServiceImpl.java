package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.constant.OpenID4VPConstants;
import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.dto.MatchingCredentialsDTO;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.VerifiablePresentation;
import io.mosip.mimoto.repository.VerifiablePresentationsRepository;
import io.mosip.mimoto.service.CredentialMatchingService;
import io.mosip.mimoto.service.KeyPairRetrievalService;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.mimoto.service.WalletPresentationService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.SigningKeyUtil;
import io.mosip.mimoto.util.Utilities;
import io.mosip.mimoto.util.UrlParameterUtils;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.common.EncoderKt;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult;
import io.mosip.openID4VP.constants.FormatType;
import io.mosip.openID4VP.verifier.VerifierResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.lang.IllegalArgumentException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.ErrorConstants.*;

/**
 * Service implementation for handling wallet presentation operations
 */
@Slf4j
@Service
public class WalletPresentationServiceImpl implements WalletPresentationService {

    private static final String DEFAULT_SIGNATURE_SUITE = "JsonWebSignature2020";
    private static final String UNKNOWN_VERIFIER = "unknown";
    private static final String EMPTY_JSON = "{}";
    private static final String DEFAULT_SIGNING_ALGORITHM_NAME = "ED25519";

    @Autowired
    private VerifierService verifierService;

    @Autowired
    private OpenID4VPService openID4VPService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private KeyPairRetrievalService keyPairService;

    @Autowired
    private CredentialMatchingService credentialMatchingService;

    @Autowired
    private VerifiablePresentationsRepository verifiablePresentationsRepository;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Override
    public VPResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId) throws ApiNotAccessibleException, IOException, URISyntaxException {
        String presentationId = UUID.randomUUID().toString();

        //Initialize OpenID4VP instance with presentationId as traceability id for each new Verifiable Presentation request
        OpenID4VP openID4VP = openID4VPService.create(presentationId);

        List<Verifier> preRegisteredVerifiers = getPreRegisteredVerifiers();
        boolean shouldValidateClient = verifierService.isVerifierClientPreregistered(preRegisteredVerifiers, urlEncodedVPAuthorizationRequest);
        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest, preRegisteredVerifiers, shouldValidateClient);
        VerifiablePresentationVerifierDTO verifiablePresentationVerifierDTO = createVPResponseVerifierDTO(preRegisteredVerifiers, authorizationRequest, walletId);

        return new VPResponseDTO(presentationId, verifiablePresentationVerifierDTO);
    }

    @Override
    public MatchingCredentialsDTO getMatchingCredentials(VerifiablePresentationSessionData sessionData, String walletId, String base64Key) throws ApiNotAccessibleException, IOException {
        log.debug("Getting matching credentials for walletId: {}, presentationId: {}", walletId, sessionData != null ? sessionData.getPresentationId() : "null");
        return credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);
    }

    @Override
    public ResponseEntity<?> handlePresentationAction(String walletId, String presentationId, SubmitPresentationRequestDTO request, VerifiablePresentationSessionData vpSessionData, String base64Key) {

        log.info("Processing presentation action for walletId: {}, presentationId: {}", walletId, presentationId);

        try {
            // Determine the action based on request content
            if (request.isSubmissionRequest()) {
                log.info("Processing presentation submission for presentationId: {}", presentationId);
                return handlePresentationSubmission(walletId, presentationId, request, vpSessionData, base64Key);

            } else if (request.isRejectionRequest()) {
                log.info("Processing verifier rejection for presentationId: {}", presentationId);
                return handleVerifierRejection(walletId, vpSessionData, request);

            } else {
                log.warn("Invalid request format - must contain either selectedCredentials or both errorCode and errorMessage");
                return Utilities.getErrorResponseEntityWithoutWrapper(new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Request must contain either selectedCredentials or both errorCode and errorMessage"), INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
            }

        } catch (JOSEException exception) {
            log.error("JWT signing error during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, JWT_SIGNING_ERROR.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (KeyGenerationException exception) {
            log.error("Key generation/retrieval error during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, KEY_GENERATION_ERROR.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (DecryptionException exception) {
            log.error("Decryption error during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, DECRYPTION_ERROR.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (ApiNotAccessibleException | IOException exception) {
            log.error("Error during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, WALLET_CREATE_VP_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (VPErrorNotSentException exception) {
            log.error("Error sending rejection to verifier for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, REJECT_VERIFIER_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (IllegalStateException exception) {
            log.error("Invalid state during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, WALLET_CREATE_VP_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (IllegalArgumentException exception) {
            log.error("Invalid argument during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        }
    }

    /**
     * Creates a VerifiablePresentationVerifierDTO from the authorization request
     */
    private VerifiablePresentationVerifierDTO createVPResponseVerifierDTO(List<Verifier> preRegisteredVerifiers, AuthorizationRequest authorizationRequest, String walletId) {
        boolean isVerifierPreRegisteredWithWallet = preRegisteredVerifiers.stream().map(Verifier::getClientId).toList().contains(authorizationRequest.getClientId());
        boolean isVerifierTrustedByWallet = verifierService.isVerifierTrustedByWallet(authorizationRequest.getClientId(), walletId);
        String clientName = Optional.ofNullable(authorizationRequest.getClientMetadata()).map(ClientMetadata::getClientName).filter(name -> !name.isBlank()).orElse(authorizationRequest.getClientId());
        String logo = Optional.ofNullable(authorizationRequest.getClientMetadata()).map(ClientMetadata::getLogoUri).orElse(null);
        return new VerifiablePresentationVerifierDTO(authorizationRequest.getClientId(), clientName, logo, isVerifierTrustedByWallet, isVerifierPreRegisteredWithWallet, authorizationRequest.getRedirectUri());
    }

    /**
     * Gets the list of pre-registered verifiers
     */
    private List<Verifier> getPreRegisteredVerifiers() throws ApiNotAccessibleException, IOException {
        return verifierService.getTrustedVerifiers().getVerifiers().stream().map(verifierDTO -> new Verifier(verifierDTO.getClientId(), verifierDTO.getResponseUris(), verifierDTO.getJwksUri(), verifierDTO.getAllowUnsignedRequest())).toList();
    }

    /**
     * Handles presentation submission with selected credentials
     */
    private ResponseEntity<SubmitPresentationResponseDTO> handlePresentationSubmission(String walletId, String presentationId, SubmitPresentationRequestDTO request, VerifiablePresentationSessionData sessionData, String base64Key) throws ApiNotAccessibleException, IOException, JOSEException, KeyGenerationException, DecryptionException {

        log.debug("Submitting presentation for walletId: {}, presentationId: {}", walletId, presentationId);

        if (base64Key == null || base64Key.isBlank()) {
            log.warn("Wallet key not found for walletId: {}", walletId);
            throw new IllegalArgumentException("Wallet key is required for presentation submission");
        }

        SubmitPresentationResponseDTO response = submitPresentation(sessionData, walletId, presentationId, request, base64Key);

        log.info("Presentation submission completed successfully for walletId: {}, presentationId: {}", walletId, presentationId);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    /**
     * Handles verifier rejection with error details
     */
    private ResponseEntity<SubmitPresentationResponseDTO> handleVerifierRejection(String walletId, VerifiablePresentationSessionData vpSessionData, SubmitPresentationRequestDTO request) throws VPErrorNotSentException {

        log.debug("Rejecting verifier for walletId: {}", walletId);

        // Create ErrorDTO from the request
        ErrorDTO errorPayload = new ErrorDTO();
        errorPayload.setErrorCode(request.getErrorCode());
        errorPayload.setErrorMessage(request.getErrorMessage());

        // Reject the verifier
        SubmitPresentationResponseDTO submitPresentationResponseDTO = rejectVerifier(walletId, vpSessionData, errorPayload);

        log.info("Verifier rejection completed successfully for walletId: {}", walletId);

        return ResponseEntity.status(HttpStatus.OK).body(submitPresentationResponseDTO);
    }

    /**
     * Rejects the verifier by sending error information
     */
    private SubmitPresentationResponseDTO rejectVerifier(String walletId, VerifiablePresentationSessionData vpSessionData, ErrorDTO payload) throws VPErrorNotSentException {
        try {
            VerifierResponse verifierResponse = openID4VPService.sendErrorToVerifier(vpSessionData, payload);
            log.info("Sent rejection to verifier. Response: {}", verifierResponse);

            SubmitPresentationResponseDTO submitPresentationResponseDTO = new SubmitPresentationResponseDTO();
            submitPresentationResponseDTO.setStatus(REJECTED_VERIFIER.getErrorCode());
            submitPresentationResponseDTO.setMessage(REJECTED_VERIFIER.getErrorMessage());
            submitPresentationResponseDTO.setRedirectUri(verifierResponse.getRedirectUri());
            return submitPresentationResponseDTO;
        } catch (ApiNotAccessibleException | IOException | URISyntaxException | IllegalArgumentException e) {
            log.error("Failed to send rejection to verifier for walletId: {} - Error: {}", walletId, e.getMessage(), e);
            throw new VPErrorNotSentException("Failed to send rejection to verifier - " + e.getMessage());
        }
    }

    /**
     * Submits a presentation with selected credentials
     */
    public SubmitPresentationResponseDTO submitPresentation(VerifiablePresentationSessionData sessionData, String walletId, String presentationId, SubmitPresentationRequestDTO request, String base64Key) throws ApiNotAccessibleException, IOException, JOSEException, KeyGenerationException, DecryptionException {

        LocalDateTime requestedAt = LocalDateTime.now();

        validateInputs(request);

        log.info("Starting presentation submission for walletId: {}, presentationId: {}", walletId, presentationId);

        // Step 1: Fetch full credentials by ID from cache
        List<DecryptedCredentialDTO> selectedCredentials = fetchSelectedCredentials(sessionData, request.getSelectedCredentials());

        // Step 2: Create OpenID4VP instance and construct unsigned VP token
        OpenID4VP openID4VP = openID4VPService.create(presentationId);
        List<Verifier> preRegisteredVerifiers = verifierService.getTrustedVerifiers().getVerifiers().stream().map(verifierDTO -> new Verifier(verifierDTO.getClientId(), verifierDTO.getResponseUris(), verifierDTO.getJwksUri(), verifierDTO.getAllowUnsignedRequest())).toList();
        openID4VP.authenticateVerifier(sessionData.getAuthorizationRequest(), preRegisteredVerifiers, sessionData.isVerifierClientPreregistered());

        // Use configurable signing algorithm
        SigningAlgorithm signingAlgorithm = SigningAlgorithm.valueOf(DEFAULT_SIGNING_ALGORITHM_NAME);
        KeyPair keyPair = keyPairService.getKeyPairFromDB(walletId, base64Key, signingAlgorithm);
        JWK jwk = SigningKeyUtil.generateJwk(signingAlgorithm, keyPair);
        Map<FormatType, UnsignedVPToken> unsignedVPToken = constructUnsignedVPToken(openID4VP, selectedCredentials, jwk);

        // Step 3: Sign token using user's private key
        JWSSigner jwsSigner = SigningKeyUtil.createSigner(signingAlgorithm, jwk);
        Map<FormatType, LdpVPTokenSigningResult> vpTokenSigningResults = signVPToken(unsignedVPToken, jwsSigner);

        // Step 4: Share verifiable presentation with verifier using OpenID4VP JAR
        log.debug("Calling OpenID4VP JAR's shareVerifiablePresentation method");
        // Cast to the expected type for the JAR method
        @SuppressWarnings({"unchecked", "rawtypes"}) Map<FormatType, VPTokenSigningResult> jarMap = (Map) vpTokenSigningResults;
        try {
            VerifierResponse response = openID4VP.sendVPResponseToVerifier(jarMap);
            boolean shareSuccess = response.getStatusCode() >= 200 && response.getStatusCode() < 300;
            // Step 5: Store presentation record in database
            storePresentationRecord(walletId, presentationId, request, sessionData, shareSuccess, requestedAt);
            // Step 6: Return success response
            return SubmitPresentationResponseDTO.builder().redirectUri(response.getRedirectUri()).status(shareSuccess ? OpenID4VPConstants.STATUS_SUCCESS : OpenID4VPConstants.STATUS_ERROR).message(shareSuccess ? OpenID4VPConstants.MESSAGE_PRESENTATION_SUCCESS : OpenID4VPConstants.MESSAGE_PRESENTATION_SHARE_FAILED).build();
        } catch (Exception e) {
            log.error("Failed to share verifiable presentation with verifier", e);
            // Store failed presentation record
            storePresentationRecord(walletId, presentationId, request, sessionData, false, requestedAt);
            return SubmitPresentationResponseDTO.builder().redirectUri(null).status(OpenID4VPConstants.STATUS_ERROR).message(OpenID4VPConstants.MESSAGE_PRESENTATION_SHARE_FAILED).build();
        }
    }

    /**
     * Signs VP token using JWSSigner for LDP_VC format
     * Only LDP_VC format is supported. Throws InvalidRequestException for other formats.
     */
    private Map<FormatType, LdpVPTokenSigningResult> signVPToken(Map<FormatType, UnsignedVPToken> unsignedVPTokensMap, JWSSigner jwsSigner) {
        log.debug("Signing VP token for {} format types", unsignedVPTokensMap.size());

        return unsignedVPTokensMap.entrySet().stream().map(entry -> {
            FormatType formatType = entry.getKey();
            UnsignedVPToken unsignedVPToken = entry.getValue();

            if (formatType != FormatType.LDP_VC) {
                log.error("Unsupported format type: {}. Only ldp_vc format is supported.", formatType);
                throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Unsupported credential format: " + formatType + ". Only ldp_vc format is supported.");
            }

            try {
                LdpVPTokenSigningResult signingResult = signLdpVcFormat(unsignedVPToken, jwsSigner);
                return Map.entry(formatType, signingResult);
            } catch (JOSEException e) {
                throw new RuntimeException("Failed to sign VP token for format: " + formatType, e);
            }
        }).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    /**
     * Signs LDP_VC format verifiable presentation using detached JWT
     */
    private LdpVPTokenSigningResult signLdpVcFormat(UnsignedVPToken unsignedVPToken, JWSSigner jwsSigner) throws JOSEException {
        log.debug("Signing LDP_VC format VP token");

        String dataToSign = ((UnsignedLdpVPToken) unsignedVPToken).getDataToSign();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).criticalParams(Set.of(OpenID4VPConstants.JWT_CRITICAL_PARAM_B64)).base64URLEncodePayload(false).build();

        // Create detached JWT signing input using EncryptionDecryptionUtil
        String headerJson = header.toString();
        byte[] inputBytes = encryptionDecryptionUtil.createDetachedJwtSigningInput(headerJson, dataToSign);
        
        // Get Base64URL encoded header for proof construction
        String header64 = EncoderKt.encodeToBase64Url(headerJson.getBytes(StandardCharsets.UTF_8));

        // Sign using the provided JWSSigner
        Base64URL signatureBase64URL = jwsSigner.sign(header, inputBytes);
        String signature = signatureBase64URL.toString();

        // Create the detached JWT proof: header64 + '..' + signature
        String proof = header64 + OpenID4VPConstants.DETACHED_JWT_SEPARATOR + signature;

        Map<String, Object> signingResultData = new HashMap<>();
        signingResultData.put(OpenID4VPConstants.JWS, proof);
        signingResultData.put(OpenID4VPConstants.PROOF_VALUE, null);
        signingResultData.put(OpenID4VPConstants.SIGNATURE_ALGORITHM, DEFAULT_SIGNATURE_SUITE);

        return objectMapper.convertValue(signingResultData, LdpVPTokenSigningResult.class);
    }

    /**
     * Fetches selected credentials from the session cache
     */
    private List<DecryptedCredentialDTO> fetchSelectedCredentials(VerifiablePresentationSessionData sessionData, List<String> selectedCredentialIds) {

        log.debug("Fetching {} selected credentials from cache", selectedCredentialIds.size());

        if (sessionData == null) {
            throw new IllegalStateException("Session data is null - cannot fetch credentials");
        }

        if (sessionData.getMatchingCredentials() == null) {
            throw new IllegalStateException("No matching credentials found in session cache");
        }

        return sessionData.getMatchingCredentials().stream().filter(credential -> selectedCredentialIds.contains(credential.getId())).collect(Collectors.toList());
    }

    /**
     * Constructs unsigned VP token using the OpenID4VP JAR
     */
    private Map<FormatType, UnsignedVPToken> constructUnsignedVPToken(OpenID4VP openID4VP, List<DecryptedCredentialDTO> credentials, JWK jwk) throws JsonProcessingException {

        log.debug("Constructing unsigned VP token for {} credentials", credentials.size());

        Map<String, Map<FormatType, List<Object>>> verifiableCredentials = convertCredentialsToJarFormat(credentials);
        String holderId = resolveHolderId(jwk);
        return openID4VP.constructUnsignedVPToken(verifiableCredentials, holderId, DEFAULT_SIGNATURE_SUITE);

    }

    /**
     * Resolves holderId from the user's public key using JWK format
     */
    private String resolveHolderId(JWK jwk) throws JsonProcessingException {

        // Convert JWK to JSON string
        String jwkJson = objectMapper.writeValueAsString(jwk.toPublicJWK().toJSONObject());

        // Base64URL encode the JWK JSON
        String base64UrlEncodedJwk = EncoderKt.encodeToBase64Url(jwkJson.getBytes(StandardCharsets.UTF_8));

        // Construct holderId: did:jwk:{base64url(jwk)}#0
        return OpenID4VPConstants.DID_JWK_PREFIX + base64UrlEncodedJwk + OpenID4VPConstants.DID_KEY_FRAGMENT;
    }

    /**
     * Converts DecryptedCredentialDTO list to the format expected by the OpenID4VP JAR
     * Extracts the inner credential data from VCCredentialResponse wrapper to remove the "credential" wrapper
     */
    private Map<String, Map<FormatType, List<Object>>> convertCredentialsToJarFormat(List<DecryptedCredentialDTO> credentials) {

        return credentials.stream().collect(Collectors.groupingBy(DecryptedCredentialDTO::getId, Collectors.collectingAndThen(Collectors.toList(), credList -> credList.stream().collect(Collectors.groupingBy(credential -> {
            // Get format and credential data
            VCCredentialResponse vcCredentialResponse = credential.getCredential();
            String credentialFormat = vcCredentialResponse.getFormat();
            // Convert format string to FormatType enum
            return mapStringToFormatType(credentialFormat);
        }, Collectors.mapping(credential -> credential.getCredential().getCredential(), Collectors.toList()))))));
    }

    /**
     * Maps format string to FormatType enum
     * Only ldp_vc format is supported. Throws InvalidRequestException for other formats.
     */
    private FormatType mapStringToFormatType(String format) {
        if (format == null) {
            log.error("Credential format is null");
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Credential format is required. Only ldp_vc format is supported.");
        }

        String formatLower = format.toLowerCase();
        if (CredentialFormat.LDP_VC.getFormat().equals(formatLower)) {
            return FormatType.LDP_VC;
        }

        log.error("Unsupported credential format: {}. Only ldp_vc format is supported.", format);
        throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Unsupported credential format: " + format + ". Only ldp_vc format is supported.");
    }

    /**
     * Stores presentation record in the database
     * Uses @Transactional to ensure atomicity of database operations
     */
    private void storePresentationRecord(String walletId, String presentationId, SubmitPresentationRequestDTO request, VerifiablePresentationSessionData sessionData, boolean success, LocalDateTime requestedAt) {
        log.debug("Storing presentation record in database - success: {}", success);

        try {
            if (sessionData == null) {
                log.warn("Session data is null for presentationId: {}", presentationId);
                return;
            }

            // Extract verifier information from OpenID4VP object
            String verifierId = extractVerifierId(sessionData);
            String authRequest = extractVerifierAuthRequest(sessionData);
            String presentationData = createPresentationData(request);

            // Create the presentation record
            VerifiablePresentation presentation = VerifiablePresentation.builder().id(presentationId).walletId(walletId).authRequest(authRequest).presentationData(presentationData).verifierId(verifierId).status(success ? OpenID4VPConstants.STATUS_SUCCESS : OpenID4VPConstants.STATUS_ERROR).requestedAt(requestedAt).consent(true).build();

            // Save to database
            verifiablePresentationsRepository.save(presentation);

            log.info("Presentation record stored successfully - recordId: {}, walletId: {}, presentationId: {}, status: {}", presentationId, walletId, presentationId, success ? OpenID4VPConstants.STATUS_SUCCESS : OpenID4VPConstants.STATUS_ERROR);

        } catch (Exception e) {
            log.error("CRITICAL: Failed to store presentation record - walletId: {}, presentationId: {}, verifierId: {}, success: {}", walletId, presentationId, sessionData != null ? extractVerifierId(sessionData) : "unknown", success, e);
        }
    }

    /**
     * Extracts verifier ID from session data
     */
    private String extractVerifierId(VerifiablePresentationSessionData sessionData) {
        try {
            // Since authorizationRequest is a URL, we need to extract client_id from URL parameters
            if (sessionData.getAuthorizationRequest() != null) {
                String authRequestUrl = sessionData.getAuthorizationRequest();
                return UrlParameterUtils.extractQueryParameter(authRequestUrl, OpenID4VPConstants.CLIENT_ID_PARAM);
            }
        } catch (Exception e) {
            log.warn("Failed to extract verifier ID", e);
        }
        return UNKNOWN_VERIFIER;
    }

    /**
     * Extracts verifier authorization request as JSON
     */
    private String extractVerifierAuthRequest(VerifiablePresentationSessionData sessionData) {
        try {
            if (sessionData.getAuthorizationRequest() != null) {
                // Convert the URL string to a JSON object
                Map<String, Object> authRequestData = new HashMap<>();
                authRequestData.put(OpenID4VPConstants.AUTHORIZATION_REQUEST_URL, sessionData.getAuthorizationRequest());
                return objectMapper.writeValueAsString(authRequestData);
            }
        } catch (Exception e) {
            log.warn("Failed to extract verifier auth request", e);
        }
        return EMPTY_JSON;
    }

    /**
     * Creates presentation data JSON with selected credentials and metadata
     */
    private String createPresentationData(SubmitPresentationRequestDTO request) {
        try {
            Map<String, Object> presentationData = new HashMap<>();
            presentationData.put(OpenID4VPConstants.SELECTED_CREDENTIALS, request.getSelectedCredentials());

            return objectMapper.writeValueAsString(presentationData);
        } catch (Exception e) {
            log.warn("Failed to create presentation data", e);
            return EMPTY_JSON;
        }
    }

    /**
     * Validates all input parameters for presentation submission
     */
    private void validateInputs(SubmitPresentationRequestDTO request) {

        if (request == null) {
            log.error("Request cannot be null");
            throw new IllegalArgumentException("Request cannot be null");
        }

        if (request.getSelectedCredentials() == null || request.getSelectedCredentials().isEmpty()) {
            log.error("Selected credentials cannot be null or empty");
            throw new IllegalArgumentException("Selected credentials cannot be null or empty");
        }

        log.debug("Input validation passed for request: {}", request);
    }
}

