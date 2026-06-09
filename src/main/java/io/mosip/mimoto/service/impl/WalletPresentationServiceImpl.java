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
import io.mosip.mimoto.service.DataProtectionService;
import io.mosip.mimoto.util.SigningKeyUtil;
import io.mosip.mimoto.util.Utilities;
import io.mosip.mimoto.util.UrlParameterUtils;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt.UnsignedSdJwtVPToken;
import io.mosip.openID4VP.common.EncoderKt;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata;
import io.mosip.mimoto.service.CredentialFormatHandlerFactory;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.sdJwt.SdJwtVPTokenSigningResult;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult;
import io.mosip.openID4VP.constants.FormatType;
import io.mosip.openID4VP.verifier.VerifierResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.lang.IllegalArgumentException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.text.ParseException;
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

    private final VerifierService verifierService;

    private final OpenID4VPService openID4VPService;

    private final ObjectMapper objectMapper;

    private final KeyPairRetrievalService keyPairService;

    private final CredentialMatchingService credentialMatchingService;

    private final VerifiablePresentationsRepository verifiablePresentationsRepository;

    private final DataProtectionService dataProtectionService;

    private final CredentialFormatHandlerFactory credentialFormatHandlerFactory;

    public WalletPresentationServiceImpl(VerifierService verifierService, OpenID4VPService openID4VPService, ObjectMapper objectMapper, KeyPairRetrievalService keyPairService, CredentialMatchingService credentialMatchingService, VerifiablePresentationsRepository verifiablePresentationsRepository, DataProtectionService dataProtectionService, CredentialFormatHandlerFactory credentialFormatHandlerFactory) {
        this.verifierService = verifierService;
        this.openID4VPService = openID4VPService;
        this.objectMapper = objectMapper;
        this.keyPairService = keyPairService;
        this.credentialMatchingService = credentialMatchingService;
        this.verifiablePresentationsRepository = verifiablePresentationsRepository;
        this.dataProtectionService = dataProtectionService;
        this.credentialFormatHandlerFactory = credentialFormatHandlerFactory;
    }

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

        // Holder key for LDP_VC is always ED25519 (Ed25519Signature2020). SD-JWT KB-JWT signing
        // derives its own per-credential key from the KB-JWT header alg inside signVPToken.
        KeyPair keyPair = keyPairService.getKeyPairFromDB(walletId, base64Key, SigningAlgorithm.ED25519);
        JWK jwk = SigningKeyUtil.generateJwk(SigningAlgorithm.ED25519, keyPair);
        Map<FormatType, UnsignedVPToken> unsignedVPToken = constructUnsignedVPToken(openID4VP, selectedCredentials, jwk, request.getSelectedSdClaims());

        // Step 3: Sign tokens - LDP_VC uses the ED25519 holder signer; SD-JWT uses per-credential signers
        Map<FormatType, JWSSigner> signers = buildFormatSigners(unsignedVPToken.keySet(), jwk);
        Map<FormatType, VPTokenSigningResult> vpTokenSigningResults = signVPToken(unsignedVPToken, signers, walletId, base64Key);

        // Step 4: Share verifiable presentation with verifier using OpenID4VP JAR
        log.debug("Calling OpenID4VP JAR's shareVerifiablePresentation method");
        try {
            VerifierResponse response = openID4VP.sendVPResponseToVerifier(vpTokenSigningResults);
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
     * Signs VP token using per-format signers - dispatches to format-specific signing logic
     */
    private Map<FormatType, VPTokenSigningResult> signVPToken(Map<FormatType, UnsignedVPToken> unsignedVPTokensMap, Map<FormatType, JWSSigner> signers, String walletId, String base64Key) throws JOSEException, KeyGenerationException, DecryptionException {
        log.debug("Signing VP token for {} format types", unsignedVPTokensMap.size());

        Map<FormatType, VPTokenSigningResult> results = new HashMap<>();
        for (Map.Entry<FormatType, UnsignedVPToken> entry : unsignedVPTokensMap.entrySet()) {
            FormatType formatType = entry.getKey();
            UnsignedVPToken unsignedVPToken = entry.getValue();

            VPTokenSigningResult signingResult;
            if (formatType == FormatType.LDP_VC) {
                signingResult = signLdpVcFormat(unsignedVPToken, signers.get(formatType));
            } else if (formatType == FormatType.VC_SD_JWT || formatType == FormatType.DC_SD_JWT) {
                // SD-JWT signers are derived per credential from the KB-JWT header alg, not from the pre-built signers map
                signingResult = signSdJwtFormat(unsignedVPToken, walletId, base64Key);
            } else {
                log.error("Unsupported format type: {}", formatType);
                throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Unsupported format type: " + formatType);
            }
            results.put(formatType, signingResult);
        }
        return results;
    }

    /**
     * Signs SD-JWT JB-JWT tokens. The library provides unsigned KB-JWTs (header.payload) per credential UUID.
     * Mimoto signs each one and returns the signatures.
     */
    private SdJwtVPTokenSigningResult signSdJwtFormat(UnsignedVPToken unsignedVPToken, String walletId, String base64Key) throws JOSEException, KeyGenerationException, DecryptionException {
        UnsignedSdJwtVPToken sdJwtToken = (UnsignedSdJwtVPToken) unsignedVPToken;
        Map<String, String> uuidToUnsignedKBT = sdJwtToken.getUuidToUnsignedKBT();

        // Cache one signer per algorithm so multiple credentials sharing an alg reuse the same key fetch
        Map<SigningAlgorithm, JWSSigner> signerCache = new EnumMap<>(SigningAlgorithm.class);

        Map<String, String> uuidToSignature = new HashMap<>();
        for (Map.Entry<String, String> entry: uuidToUnsignedKBT.entrySet()) {
            String uuid = entry.getKey();
            // "headerB64.payloadB64"
            String unsignedKBT = entry.getValue();

            // Parse the KB-JWT header produced by the OpenID4VP JAR and read its alg.
            // The JAR derives this alg from the credential's cnf, so the header is the source of truth.
            JWSHeader kbHeader;
            try {
                String[] parts = unsignedKBT.split("\\.");
                kbHeader = JWSHeader.parse(new Base64URL(parts[0]));
            } catch (ParseException e) {
                throw new JOSEException("Failed to parse KB-JWT header for credential uuid: " + uuid, e);
            }

            SigningAlgorithm algorithm = SigningAlgorithm.fromString(kbHeader.getAlgorithm().getName());

            // Build (or reuse) a signer for this algorithm using the wallet's key pair for that alg
            JWSSigner jwsSigner = signerCache.get(algorithm);
            if (jwsSigner == null) {
                KeyPair keyPair = keyPairService.getKeyPairFromDB(walletId, base64Key, algorithm);
                JWK jwk = SigningKeyUtil.generateJwk(algorithm, keyPair);
                jwsSigner = SigningKeyUtil.createSigner(algorithm, jwk);
                signerCache.put(algorithm, jwsSigner);
            }

            // Standard JWT signing input: ASCII bytes of "headerB64.payloadB64"
            byte[] signingInput = unsignedKBT.getBytes(StandardCharsets.US_ASCII);

            Base64URL signature = jwsSigner.sign(kbHeader, signingInput);
            uuidToSignature.put(uuid, signature.toString());
        }

        return new SdJwtVPTokenSigningResult(uuidToSignature);
    }

    /**
     * Signs LDP_VC format verifiable presentation using detached JWT
     */
    private LdpVPTokenSigningResult signLdpVcFormat(UnsignedVPToken unsignedVPToken, JWSSigner jwsSigner) throws JOSEException {
        log.debug("Signing LDP_VC format VP token");

        String dataToSign = ((UnsignedLdpVPToken) unsignedVPToken).getDataToSign();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).criticalParams(Set.of(OpenID4VPConstants.JWT_CRITICAL_PARAM_B64)).base64URLEncodePayload(false).build();

        // Create detached JWT signing input using DataProtectionService
        String headerJson = header.toString();
        byte[] inputBytes = dataProtectionService.createDetachedJwtSigningInput(headerJson, dataToSign);
        
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
     * Constructs unsigned VP token using the OpenID4VP JAR.
     * For SD-JWT credentials, disclosures are pre-filtered to the user's selectedSdClaims.
     */
    private Map<FormatType, UnsignedVPToken> constructUnsignedVPToken(OpenID4VP openID4VP, List<DecryptedCredentialDTO> credentials, JWK jwk, Map<String, List<String>> selectedSdClaims) throws JsonProcessingException {

        log.debug("Constructing unsigned VP token for {} credentials", credentials.size());

        Map<String, Map<FormatType, List<Object>>> verifiableCredentials = convertCredentialsToJarFormat(credentials, selectedSdClaims);
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
     * Converts DecryptedCredentialDTO list to the format expected by the OpenID4VP JAR.
     * Extracts the inner credential data from VCCredentialResponse wrapper to remove the "credential" wrapper.
     * For SD-JWT credentials, filters disclosures down to only the user-selected claims.
     */
    private Map<String, Map<FormatType, List<Object>>> convertCredentialsToJarFormat(List<DecryptedCredentialDTO> credentials, Map<String, List<String>> selectedSdClaims) {
        Map<String, Map<FormatType, List<Object>>> result = new HashMap<>();

        for (DecryptedCredentialDTO credential: credentials) {
            VCCredentialResponse vcResponse = credential.getCredential();
            String format = vcResponse.getFormat();
            FormatType formatType = mapStringToFormatType(format);

            Object credentialData;
            if(CredentialFormat.isSdJwt(format)) {
                List<String> selectedPaths = selectedSdClaims != null ? selectedSdClaims.get(credential.getId()) : null;
                credentialData = buildFilteredSdJwt(credential, selectedPaths);
            } else {
                credentialData = vcResponse.getCredential();
            }

            result.computeIfAbsent(credential.getId(), k -> new HashMap<>())
                    .computeIfAbsent(formatType, k -> new ArrayList<>())
                    .add(credentialData);
        }

        return result;
    }

    /**
     * Maps format string to FormatType enum.
     */
    private FormatType mapStringToFormatType(String format) {
        if (format == null) {
            log.error("Credential format is null");
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Credential format is required.");
        }

        String formatLower = format.toLowerCase();
        if (CredentialFormat.LDP_VC.getFormat().equals(formatLower)) return FormatType.LDP_VC;
        if (CredentialFormat.VC_SD_JWT.getFormat().equals(formatLower)) return FormatType.VC_SD_JWT;
        if (CredentialFormat.DC_SD_JWT.getFormat().equals(formatLower)) return FormatType.DC_SD_JWT;

        log.error("Unsupported credential format: {}", format);
        throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Unsupported credential format: " + format);
    }

    /**
     * Builds an SD-JWT string containing ONLY the user-selected disclosures.
     * Disclosures are shared only when explicitly selected; if selectedPaths is null/empty
     * (the user selected no SD claims for this credential), no disclosures are shared.
     */
    private String buildFilteredSdJwt(DecryptedCredentialDTO credential, List<String> selectedPaths) {
        if (!(credential.getCredential().getCredential() instanceof String sdJwtString)) {
            log.warn("Credential {} payload is not a String; skipping SD-JWT filtering", credential.getId());
            return String.valueOf(credential.getCredential().getCredential());
        }

        // The issuer-signed credential JWT is everything before the first '~'.
        // We rebuild from this and append ONLY the explicitly selected disclosures - never all.
        String credentialJwt = sdJwtString.split("~", -1)[0];

        // No selection for this credential -> user chose to disclose nothing -> share zero disclosures
        if (selectedPaths == null || selectedPaths.isEmpty()) {
            return credentialJwt + "~";
        }

        try {
            // Get path -> List <disclosuresB64> mapping from the format handler
            Map<String, ?> allProps = credentialFormatHandlerFactory
                    .getHandler(credential.getCredential().getFormat())
                    .extractAllCredentialProperties(credential.getCredential());

            if (!(allProps.get("sdClaims") instanceof Map<?, ?> rawSdClaims)) {
                return credentialJwt + "~";
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> sdClaimsMap = (Map<String, Object>) rawSdClaims;
            if (sdClaimsMap.isEmpty()) {
                return credentialJwt + "~";
            }

            // Normalize paths: "$.name" -> "name", "$.address.city" -> "address.city"
            Set<String> normalizedPaths = selectedPaths.stream().
                    map(p -> p.startsWith("$.") ? p.substring(2) : p)
                    .collect(Collectors.toCollection(LinkedHashSet::new));

            // Collect all disclosures B64 strings for the selected paths (preserving order, deduplicating)
            Set<String> allDisclosuresB64 = new LinkedHashSet<>();
            for (String path : normalizedPaths) {
                Object disclosures = sdClaimsMap.get(path);
                if (disclosures instanceof List<?> discList) {
                    discList.forEach(d -> allDisclosuresB64.add((String) d));
                }
            }

            // Reconstruct: credentialJwt ~ disc1 ~ disc2 ~ (trailing ~ required by SD-JWT)
            StringBuilder sb = new StringBuilder(credentialJwt);
            for (String disc: allDisclosuresB64) {
                sb.append("~").append(disc);
            }
            sb.append("~");
            return sb.toString();

        } catch (Exception e) {
            log.error("Failed to filter SD-JWT disclosures for credential: {}, selectedPaths: {}. Sharing no disclosures. Error: {}", credential.getId(), selectedPaths, e.getMessage(), e);
            return credentialJwt + "~";
        }
    }

    /**
     * Builds the LDP_VC signer from the ED25519 holder key.
     * SD-JWT signers are derived per credential from the KB-JWT header alg in signVPToken, so they are not built here.
     */
    private Map<FormatType, JWSSigner> buildFormatSigners(Set<FormatType> formats, JWK ed25519Jwk) throws JOSEException {
        Map<FormatType, JWSSigner> signers = new EnumMap<>(FormatType.class);
        if (formats.contains(FormatType.LDP_VC)) {
            signers.put(FormatType.LDP_VC, SigningKeyUtil.createSigner(SigningAlgorithm.ED25519, ed25519Jwk));
        }
        return signers;
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

