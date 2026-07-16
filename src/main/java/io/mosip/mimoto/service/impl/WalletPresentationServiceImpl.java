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
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.VerifiablePresentation;
import io.mosip.mimoto.repository.VerifiablePresentationsRepository;
import io.mosip.mimoto.service.*;
import io.mosip.mimoto.util.AuthorizationRequestHelper;
import io.mosip.mimoto.util.SigningKeyUtil;
import io.mosip.mimoto.util.Utilities;
import io.mosip.mimoto.util.UrlParameterUtils;
import io.mosip.mimoto.util.DcqlClaimSetHelper;
import io.mosip.mimoto.util.DcqlMatchingHelper;
import io.mosip.mimoto.util.DcqlCredentialSetHelper;
import io.mosip.mimoto.util.SelectedSdClaimsUtil;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult;
import io.mosip.openID4VP.constants.FormatType;
import io.mosip.openID4VP.dcql.query.ClaimsQuery;
import io.mosip.openID4VP.dcql.query.CredentialQuery;
import io.mosip.openID4VP.dcql.query.CredentialSetQuery;
import io.mosip.openID4VP.dcql.query.DCQLQuery;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;
import io.mosip.openID4VP.verifier.VerifierResponse;
import io.mosip.openID4VP.wallet.Credential;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.ErrorConstants.*;

/**
 * Service implementation for handling wallet presentation operations.
 */
@Slf4j
@Service
public class WalletPresentationServiceImpl implements WalletPresentationService {

    private static final String UNKNOWN_VERIFIER = "unknown";
    private static final String EMPTY_JSON = "{}";

    private final VerifierService verifierService;
    private final OpenID4VPService openID4VPService;
    private final ObjectMapper objectMapper;
    private final KeyPairRetrievalService keyPairService;
    private final CredentialMatchingService credentialMatchingService;
    private final VerifiablePresentationsRepository verifiablePresentationsRepository;
    private final CredentialFormatHandlerFactory credentialFormatHandlerFactory;
    private final WalletCredentialService walletCredentialService;

    public WalletPresentationServiceImpl(
            VerifierService verifierService,
            OpenID4VPService openID4VPService,
            ObjectMapper objectMapper,
            KeyPairRetrievalService keyPairService,
            CredentialMatchingService credentialMatchingService,
            VerifiablePresentationsRepository verifiablePresentationsRepository,
            CredentialFormatHandlerFactory credentialFormatHandlerFactory,
            WalletCredentialService walletCredentialService) {
        this.verifierService = verifierService;
        this.openID4VPService = openID4VPService;
        this.objectMapper = objectMapper;
        this.keyPairService = keyPairService;
        this.credentialMatchingService = credentialMatchingService;
        this.verifiablePresentationsRepository = verifiablePresentationsRepository;
        this.credentialFormatHandlerFactory = credentialFormatHandlerFactory;
        this.walletCredentialService = walletCredentialService;
    }

    @Override
    public VPResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId)
            throws ApiNotAccessibleException, IOException, URISyntaxException {

        String presentationId = UUID.randomUUID().toString();
        // Initialize OpenID4VP instance with presentationId as traceability id for each new Verifiable Presentation request
        List<Verifier> preRegisteredVerifiers = openID4VPService.getPreRegisteredVerifiers();
        boolean shouldValidateClient = verifierService.isVerifierClientPreregistered(
                preRegisteredVerifiers, urlEncodedVPAuthorizationRequest);

        OpenID4VP openID4VP = openID4VPService.create(presentationId, preRegisteredVerifiers, shouldValidateClient);
        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest);
        boolean dcql = AuthorizationRequestHelper.hasDcqlQuery(authorizationRequest);

        VerifiablePresentationVerifierDTO verifierDTO =
                createVPResponseVerifierDTO(preRegisteredVerifiers, authorizationRequest, walletId);

        return new VPResponseDTO(presentationId, verifierDTO, dcql);
    }

    @Override
    public MatchingCredentialsDTO getMatchingCredentials(
            VerifiablePresentationSessionData sessionData, String walletId, String base64Key)
            throws ApiNotAccessibleException, IOException {
        return credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);
    }

    @Override
    public ResponseEntity<?> handlePresentationAction(
            String walletId, String presentationId, SubmitPresentationRequestDTO request,
            VerifiablePresentationSessionData vpSessionData, String base64Key) {

        try {
            // Determine the action based on request content
            if (request.isSubmissionRequest()) {
                if (base64Key == null || base64Key.isBlank()) {
                    return Utilities.getErrorResponseEntityWithoutWrapper(
                            new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                                    "Wallet key is required for credential presentation"),
                            INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
                }
                SubmitPresentationResponseDTO response =
                        submitPresentation(vpSessionData, walletId, presentationId, request, base64Key);
                return ResponseEntity.ok(response);
            }
            if (request.isRejectionRequest()) {
                return handleVerifierRejection(walletId, vpSessionData, request);
            }
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                            "Request must contain selectedCredentials / dcqlSelections or both errorCode and errorMessage"),
                    INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);

        } catch (JOSEException ex) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    ex, JWT_SIGNING_ERROR.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        } catch (KeyGenerationException | DecryptionException ex) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    ex, KEY_GENERATION_ERROR.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        } catch (ApiNotAccessibleException | IOException ex) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    ex, WALLET_CREATE_VP_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        } catch (VPErrorNotSentException ex) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    ex, REJECT_VERIFIER_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        } catch (IllegalStateException | java.lang.IllegalArgumentException ex) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    ex, INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        } catch (OpenID4VPExceptions ex) {
            log.error("OpenID4VP error during presentation submission for presentationId={}", presentationId, ex);
            if (ex.getCause() != null) {
                log.error("OpenID4VP root cause for presentationId={}: {}", presentationId,
                        ex.getCause().getMessage(), ex.getCause());
            }
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    ex, ex.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        }
    }

    /**
     * Submits a presentation with selected credentials (Draft-23 or DCQL).
     */
    public SubmitPresentationResponseDTO submitPresentation(
            VerifiablePresentationSessionData sessionData, String walletId, String presentationId,
            SubmitPresentationRequestDTO request, String base64Key)
            throws ApiNotAccessibleException, IOException, JOSEException,
                   KeyGenerationException, DecryptionException, OpenID4VPExceptions {

        validateSubmissionRequest(request);
        LocalDateTime requestedAt = LocalDateTime.now();

        // Step 1: Create OpenID4VP instance and authenticate the verifier from session data
        List<Verifier> preRegisteredVerifiers = openID4VPService.getPreRegisteredVerifiers();
        OpenID4VP openID4VP = openID4VPService.create(
                presentationId, preRegisteredVerifiers, sessionData.isVerifierClientPreregistered());
        openID4VP.authenticateVerifier(sessionData.getAuthorizationRequest());

        // Step 2: Load wallet credentials and resolve effective SD-JWT claim paths for submission
        Map<String, DecryptedCredentialDTO> walletCredentialsById = walletCredentialService
                .getDecryptedCredentials(walletId, base64Key).stream()
                .collect(Collectors.toMap(DecryptedCredentialDTO::getId, dto -> dto, (a, b) -> a));

        if (request.isDcqlSubmission()) {
            validateDcqlSelections(request, sessionData);
        }

        Map<String, List<String>> effectiveSelectedSdClaims =
                resolveSubmissionSdClaims(request, sessionData, walletCredentialsById);

        // Step 3: Build credential map for inji-openid4vp (descriptor-based for Draft-23, query-based for DCQL)
        Map<String, List<Credential>> credentialMap;
        if (request.isDcqlSubmission()) {
            credentialMap = buildQueryCredentialMap(
                    request.getDcqlSelections(), sessionData, effectiveSelectedSdClaims, walletCredentialsById);
        } else {
            List<DecryptedCredentialDTO> selected = fetchSelectedCredentials(
                    sessionData, request.getSelectedCredentialIds());
            credentialMap = buildDescriptorCredentialMap(selected, effectiveSelectedSdClaims, walletCredentialsById);
        }

        // Step 4: Construct unsigned VP tokens and sign them
        List<UnsignedVPToken> unsignedVPTokens = openID4VP.constructUnsignedVPToken(credentialMap);
        List<VPTokenSigningResult> signingResults = signVPTokens(unsignedVPTokens, walletId, base64Key);

        // Step 5: Share verifiable presentation with verifier using OpenID4VP JAR
        try {
            VerifierResponse response = openID4VP.sendVPResponseToVerifier(signingResults);
            boolean success = response.getStatusCode() >= 200 && response.getStatusCode() < 300;
            // Step 6: Store presentation record in database
            storePresentationRecord(walletId, presentationId, request, sessionData, success, requestedAt);
            return buildSubmitResponse(
                    success,
                    response.getRedirectUri(),
                    success ? OpenID4VPConstants.MESSAGE_PRESENTATION_SUCCESS
                            : OpenID4VPConstants.MESSAGE_PRESENTATION_SHARE_FAILED);
        } catch (Exception ex) {
            log.error("Failed to send VP to verifier for presentationId={}", presentationId, ex);
            storePresentationRecord(walletId, presentationId, request, sessionData, false, requestedAt);
            return buildSubmitResponse(
                    false, null, OpenID4VPConstants.MESSAGE_PRESENTATION_SHARE_FAILED);
        }
    }

    private SubmitPresentationResponseDTO buildSubmitResponse(boolean success, String redirectUri, String message) {
        return SubmitPresentationResponseDTO.builder()
                .redirectUri(redirectUri)
                .status(success ? OpenID4VPConstants.STATUS_SUCCESS : OpenID4VPConstants.STATUS_ERROR)
                .message(message)
                .build();
    }

    /**
     * Builds Draft-23 credential map keyed by input descriptor id.
     */
    private Map<String, List<Credential>> buildDescriptorCredentialMap(
            List<DecryptedCredentialDTO> selected,
            Map<String, List<String>> selectedSdClaims,
            Map<String, DecryptedCredentialDTO> walletCredentialsById) {

        Map<String, List<Credential>> result = new LinkedHashMap<>();
        for (DecryptedCredentialDTO dto : selected) {
            DecryptedCredentialDTO credentialForSubmission = resolveCredentialForSubmission(dto, walletCredentialsById);
            String key = (credentialForSubmission.getIdentifier() != null && !credentialForSubmission.getIdentifier().isBlank())
                    ? credentialForSubmission.getIdentifier() : credentialForSubmission.getId();
            result.computeIfAbsent(key, k -> new ArrayList<>())
                    .add(toLibraryCredential(credentialForSubmission, selectedSdClaims));
        }
        return result;
    }

    /**
     * Builds DCQL credential map keyed by query id.
     */
    private Map<String, List<Credential>> buildQueryCredentialMap(
            List<DcqlCredentialSelection> selections,
            VerifiablePresentationSessionData sessionData,
            Map<String, List<String>> effectiveSdClaims,
            Map<String, DecryptedCredentialDTO> walletCredentialsById) {

        Map<String, DecryptedCredentialDTO> cache = Optional.ofNullable(sessionData.getMatchingCredentials())
                .orElse(List.of()).stream()
                .collect(Collectors.toMap(DecryptedCredentialDTO::getId, d -> d));

        Map<String, List<Credential>> result = new LinkedHashMap<>();
        for (DcqlCredentialSelection selection : selections) {
            List<Credential> credentials = new ArrayList<>();
            for (String id : selection.getSelectedCredentialIds()) {
                DecryptedCredentialDTO sessionDto = cache.get(id);
                if (sessionDto == null) {
                    throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                            "Selected credential not found in session: " + id);
                }
                if (sessionDto.getIdentifier() == null || sessionDto.getIdentifier().isBlank()) {
                    throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                            "Credential " + id + " has no query mapping — call GET /credentials before submit");
                }
                DecryptedCredentialDTO credentialForSubmission =
                        resolveCredentialForSubmission(sessionDto, walletCredentialsById);
                credentials.add(toLibraryCredential(credentialForSubmission, effectiveSdClaims));
            }
            String mapKey = resolveDcqlMapKey(selection, cache);
            result.merge(mapKey, credentials, (existing, incoming) -> {
                List<Credential> merged = new ArrayList<>(existing);
                merged.addAll(incoming);
                return merged;
            });
        }
        return result;
    }

    /**
     * Resolves the DCQL query id used as the inji-openid4vp map key. The client-supplied
     * {@code queryId} is authoritative when present, since one wallet credential may match
     * multiple DCQL queries and the session stores only the first match's identifier.
     */
    private String resolveDcqlMapKey(DcqlCredentialSelection selection, Map<String, DecryptedCredentialDTO> cache) {
        if (selection.getQueryId() != null && !selection.getQueryId().isBlank()) {
            return selection.getQueryId();
        }
        List<String> selectedIds = selection.getSelectedCredentialIds();
        if (selectedIds == null || selectedIds.isEmpty()) {
            return selection.getQueryId();
        }
        String sessionQueryId = null;
        for (String id : selectedIds) {
            DecryptedCredentialDTO dto = cache.get(id);
            if (dto == null || dto.getIdentifier() == null || dto.getIdentifier().isBlank()) {
                continue;
            }
            if (sessionQueryId == null) {
                sessionQueryId = dto.getIdentifier();
            } else if (!sessionQueryId.equals(dto.getIdentifier())) {
                throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                        "Selected credentials belong to different DCQL queries: "
                                + sessionQueryId + " vs " + dto.getIdentifier());
            }
        }
        return sessionQueryId;
    }

    /**
     * Merges session credential metadata with the latest decrypted credential payload from the wallet.
     */
    private DecryptedCredentialDTO resolveCredentialForSubmission(
            DecryptedCredentialDTO sessionDto, Map<String, DecryptedCredentialDTO> walletCredentialsById) {
        DecryptedCredentialDTO walletDto = walletCredentialsById.get(sessionDto.getId());
        if (walletDto == null) {
            return sessionDto;
        }
        return DecryptedCredentialDTO.builder()
                .id(sessionDto.getId())
                .walletId(walletDto.getWalletId())
                .credential(walletDto.getCredential())
                .credentialMetadata(walletDto.getCredentialMetadata())
                .createdAt(walletDto.getCreatedAt())
                .updatedAt(walletDto.getUpdatedAt())
                .identifier(sessionDto.getIdentifier())
                .build();
    }

    /**
     * Converts a wallet credential to the inji-openid4vp {@link Credential} type.
     * For SD-JWT credentials, disclosures are pre-filtered to the user's selectedSdClaims.
     */
    private Credential toLibraryCredential(DecryptedCredentialDTO dto, Map<String, List<String>> selectedSdClaims) {
        VCCredentialResponse vc = dto.getCredential();
        if (CredentialFormat.isSdJwt(vc.getFormat())) {
            FormatType format = mapToFormatType(vc.getFormat());
            String sdJwt = buildFilteredSdJwt(
                    dto, selectedSdClaims != null ? selectedSdClaims.get(dto.getId()) : null);
            return new Credential(format, sdJwt, dto.getId());
        }
        if (!CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(vc.getFormat())) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                    "Unsupported credential format: " + vc.getFormat());
        }
        // inji-openid4vp expects LDP credentials as a JSON object (Map), not a typed POJO.
        Credential mapped = DcqlMatchingHelper.toLibraryCredential(dto, objectMapper);
        if (mapped == null) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                    "Credential " + dto.getId() + " could not be mapped for OpenID4VP submission");
        }
        log.info("mapped>>>>>> {}", mapped);
        return mapped;
    }

    private void validateDcqlSelections(SubmitPresentationRequestDTO request, VerifiablePresentationSessionData sessionData)
            throws ApiNotAccessibleException, IOException {

        DCQLQuery dcqlQuery = openID4VPService.resolveDcqlQuery(
                sessionData.getPresentationId(),
                sessionData.getAuthorizationRequest(),
                sessionData.isVerifierClientPreregistered());
        if (dcqlQuery == null) {
            return;
        }

        Set<String> validQueryIds = dcqlQuery.getCredentials().stream()
                .map(CredentialQuery::getId)
                .collect(Collectors.toSet());

        Map<String, DecryptedCredentialDTO> sessionById = Optional.ofNullable(sessionData.getMatchingCredentials())
                .orElse(List.of()).stream()
                .collect(Collectors.toMap(DecryptedCredentialDTO::getId, d -> d, (a, b) -> a));

        Map<String, Integer> selectionCount = new LinkedHashMap<>();
        for (DcqlCredentialSelection selection : request.getDcqlSelections()) {
            String resolvedQueryId = resolveDcqlMapKey(selection, sessionById);
            int count = selection.getSelectedCredentialIds() != null ? selection.getSelectedCredentialIds().size() : 0;
            selectionCount.merge(resolvedQueryId, count, Integer::sum);

            if (!validQueryIds.contains(resolvedQueryId)) {
                throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                        "Unknown DCQL query id '" + resolvedQueryId + "'. Valid query ids: " + validQueryIds);
            }
        }

        for (CredentialQuery query : dcqlQuery.getCredentials()) {
            if (!query.getMultiple()) {
                int count = selectionCount.getOrDefault(query.getId(), 0);
                if (count > 1) {
                    throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                            "DCQL query '" + query.getId() + "' has multiple=false but " + count + " credential(s) were selected");
                }
            }
        }

        for (CredentialSetQuery setQuery : DcqlCredentialSetHelper.resolveEffectiveCredentialSets(dcqlQuery)) {
            if (!setQuery.getRequired()) {
                continue;
            }
            Set<String> allQidsInSet = setQuery.getOptions().stream()
                    .flatMap(List::stream)
                    .collect(Collectors.toCollection(LinkedHashSet::new));

            Set<String> selectedForSet = allQidsInSet.stream()
                    .filter(qid -> selectionCount.getOrDefault(qid, 0) > 0)
                    .collect(Collectors.toCollection(LinkedHashSet::new));

            boolean exactlyOneOptionMatched = setQuery.getOptions().stream()
                    .anyMatch(option -> new LinkedHashSet<>(option).equals(selectedForSet));

            if (!exactlyOneOptionMatched) {
                throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                        "Credential selection must satisfy exactly one option in credential_set. " +
                        "Selected query ids: " + selectedForSet + ", Options: " + setQuery.getOptions());
            }
        }
    }

    /**
     * Merges explicit {@code selectedSdClaims} with DCQL {@code claim_sets} resolution.
     * When a query defines {@code claim_sets} and the client omits {@code selectedSdClaims} for a credential,
     * the first satisfiable claim set (or {@code selectedClaimIds}) determines which SD-JWT paths are disclosed.
     */
    private Map<String, List<String>> resolveSubmissionSdClaims(
            SubmitPresentationRequestDTO request,
            VerifiablePresentationSessionData sessionData,
            Map<String, DecryptedCredentialDTO> walletCredentialsById)
            throws ApiNotAccessibleException, IOException {

        Map<String, List<String>> merged = new LinkedHashMap<>();
        Map<String, List<String>> explicit = request.resolveEffectiveSelectedSdClaims();
        SelectedSdClaimsUtil.mergeInto(merged, explicit);
        if (!request.isDcqlSubmission()) {
            return merged.isEmpty() ? null : merged;
        }

        DCQLQuery dcqlQuery = openID4VPService.resolveDcqlQuery(
                sessionData.getPresentationId(),
                sessionData.getAuthorizationRequest(),
                sessionData.isVerifierClientPreregistered());
        if (dcqlQuery == null) {
            return merged.isEmpty() ? null : merged;
        }

        Map<String, CredentialQuery> queriesById = dcqlQuery.getCredentials().stream()
                .collect(Collectors.toMap(CredentialQuery::getId, q -> q, (a, b) -> a, LinkedHashMap::new));
        Map<String, DecryptedCredentialDTO> sessionById = Optional.ofNullable(sessionData.getMatchingCredentials())
                .orElse(List.of()).stream()
                .collect(Collectors.toMap(DecryptedCredentialDTO::getId, d -> d, (a, b) -> a));

        for (DcqlCredentialSelection selection : request.getDcqlSelections()) {
            String queryId = resolveDcqlMapKey(selection, sessionById);
            CredentialQuery credentialQuery = queriesById.get(queryId);
            if (credentialQuery == null || selection.getSelectedCredentialIds() == null) {
                continue;
            }
            for (String credentialId : selection.getSelectedCredentialIds()) {
                if (hasExplicitSdClaimsForCredential(explicit, credentialId, selection)) {
                    continue;
                }
                DecryptedCredentialDTO sessionDto = sessionById.get(credentialId);
                if (sessionDto == null) {
                    continue;
                }
                DecryptedCredentialDTO credForSd =
                        resolveCredentialForSubmission(sessionDto, walletCredentialsById);
                Map<String, Object> sdClaimsMap = extractSdClaimsMap(credForSd);

                if (DcqlClaimSetHelper.hasClaimSets(credentialQuery)) {
                    // claim_sets present: resolve the first satisfiable set
                    List<String> claimIds = DcqlClaimSetHelper.resolveClaimIdsForSubmission(
                            credentialQuery,
                            null,
                            path -> sdClaimsMap != null && hasDisclosureForPath(sdClaimsMap, path));
                    List<String> claimPaths = DcqlClaimSetHelper.resolveClaimPaths(credentialQuery, claimIds);
                    if (!claimPaths.isEmpty()) {
                        SelectedSdClaimsUtil.mergePaths(merged, credentialId, claimPaths);
                        log.info("DCQL claim_sets resolved for credential {} query '{}': claimIds={}, paths={}",
                                credentialId, queryId, claimIds, claimPaths);
                    }
                } else {
                    // No claim_sets: per DCQL spec §6, all queried claims that have SD
                    // disclosures in this credential must be included in the VP.
                    resolveAllQueriedSdClaims(credentialQuery, credentialId, sdClaimsMap, merged, queryId);
                }
            }
        }
        return merged.isEmpty() ? null : merged;
    }

    private boolean hasExplicitSdClaimsForCredential(
            Map<String, List<String>> explicit,
            String credentialId,
            DcqlCredentialSelection selection) {
        if (explicit != null && explicit.containsKey(credentialId)) {
            return true;
        }
        return selection.getSelectedSdClaims() != null && selection.getSelectedSdClaims().containsKey(credentialId);
    }

    /**
     * When {@code claim_sets} is absent, all claims in {@code CredentialQuery.getClaims()} that have
     * an SD disclosure in the credential must be included in the VP per DCQL spec §6.
     * Public claims (those in the JWT payload, not in SD disclosures) are skipped — they are
     * always present in the credential JWT and require no explicit selection.
     */
    private void resolveAllQueriedSdClaims(CredentialQuery credentialQuery, String credentialId,
            Map<String, Object> sdClaimsMap, Map<String, List<String>> merged, String queryId) {
        List<ClaimsQuery> claims = credentialQuery.getClaims();
        if (claims == null || claims.isEmpty()) {
            return;
        }
        List<String> sdPaths = claims.stream()
                .filter(cq -> cq.getPath() != null && !cq.getPath().isEmpty())
                .map(cq -> DcqlClaimSetHelper.buildClaimPath(cq.getPath()))
                .filter(path -> sdClaimsMap != null && hasDisclosureForPath(sdClaimsMap, path))
                .collect(Collectors.toList());
        if (!sdPaths.isEmpty()) {
            SelectedSdClaimsUtil.mergePaths(merged, credentialId, sdPaths);
            log.info("DCQL all-claims resolved for credential {} query '{}': paths={}",
                    credentialId, queryId, sdPaths);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> extractSdClaimsMap(DecryptedCredentialDTO dto) {
        try {
            if (!CredentialFormat.isSdJwt(dto.getCredential().getFormat())) {
                return null;
            }
            Map<String, ?> allProps = credentialFormatHandlerFactory
                    .getHandler(dto.getCredential().getFormat())
                    .extractAllCredentialProperties(dto.getCredential());
            if (allProps == null || !(allProps.get("sdClaims") instanceof Map<?, ?> raw)) {
                return null;
            }
            return (Map<String, Object>) raw;
        } catch (Exception e) {
            log.warn("Could not extract sdClaims for credential {}: {}", dto.getId(), e.getMessage());
            return null;
        }
    }

    private boolean hasDisclosureForPath(Map<String, Object> sdClaimsMap, String claimPath) {
        String normalized = normalizeSdClaimPath(claimPath);
        Object disc = resolveSdClaimDisclosures(sdClaimsMap, normalized);
        if (disc instanceof List<?> list) {
            return !list.isEmpty();
        }
        return disc instanceof String s && !s.isBlank();
    }

    /**
     * Signs each unsigned VP token. LDP_VC uses detached JWT signing; SD-JWT signs the KB-JWT
     * payload bytes provided by the library. Signers are cached per algorithm.
     */
    private List<VPTokenSigningResult> signVPTokens(
            List<UnsignedVPToken> tokens, String walletId, String base64Key)
            throws JOSEException, KeyGenerationException, DecryptionException {

        List<VPTokenSigningResult> results = new ArrayList<>();
        // Cache one signer per algorithm so multiple credentials sharing an alg reuse the same key fetch
        Map<SigningAlgorithm, JWSSigner> signerCache = new EnumMap<>(SigningAlgorithm.class);

        for (UnsignedVPToken token : tokens) {
            SigningAlgorithm algorithm = SigningAlgorithm.fromString(
                    Optional.ofNullable(token.getSignatureAlgorithm()).filter(s -> !s.isBlank())
                            .orElse(SigningAlgorithm.ED25519.getJWSAlgorithm().getName()));

            JWSSigner signer = signerCache.get(algorithm);
            if (signer == null) {
                KeyPair keyPair = keyPairService.getKeyPairFromDB(walletId, base64Key, algorithm);
                JWK jwk = SigningKeyUtil.generateJwk(algorithm, keyPair);
                signer = SigningKeyUtil.createSigner(algorithm, jwk);
                signerCache.put(algorithm, signer);
            }

            byte[] dataToSign = token.getDataToSign();
            Base64URL signature;
            try {
                if (token.getFormat() == FormatType.LDP_VC) {
                    // LDP_VC: sign payload bytes after the first '.' separator
                    int dotIndex = indexOfDot(dataToSign);
                    String headerB64 = new String(dataToSign, 0, dotIndex, StandardCharsets.US_ASCII);
                    byte[] payload = Arrays.copyOfRange(dataToSign, dotIndex + 1, dataToSign.length);
                    JWSHeader header = JWSHeader.parse(new Base64URL(headerB64));
                    signature = signer.sign(header, payload);
                } else {
                    // SD-JWT: standard JWT signing input is ASCII bytes of "headerB64.payloadB64"
                    String unsignedJwt = new String(dataToSign, StandardCharsets.US_ASCII);
                    String headerB64 = unsignedJwt.substring(0, unsignedJwt.indexOf('.'));
                    JWSHeader header = JWSHeader.parse(new Base64URL(headerB64));
                    signature = signer.sign(header, dataToSign);
                }
            } catch (ParseException e) {
                throw new JOSEException("Failed to parse JWS header for VP token signing", e);
            }
            results.add(new VPTokenSigningResult(token.getId(), signature.decode()));
        }
        return results;
    }

    private int indexOfDot(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == '.') {
                return i;
            }
        }
        throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Invalid LDP dataToSign: missing '.' separator");
    }

    /**
     * Builds an SD-JWT string containing only the user-selected disclosures.
     * If selectedPaths is null/empty, no disclosures are shared for that credential.
     */
    private String buildFilteredSdJwt(DecryptedCredentialDTO credential, List<String> selectedPaths) {
        if (!(credential.getCredential().getCredential() instanceof String sdJwtString)) {
            return String.valueOf(credential.getCredential().getCredential());
        }
        // The issuer-signed credential JWT is everything before the first '~'
        String credentialJwt = sdJwtString.split("~", -1)[0];
        // No selection for this credential -> share zero disclosures
        if (selectedPaths == null || selectedPaths.isEmpty()) {
            return credentialJwt + "~";
        }
        try {
            Map<String, ?> allProps = credentialFormatHandlerFactory
                    .getHandler(credential.getCredential().getFormat())
                    .extractAllCredentialProperties(credential.getCredential());
            if (!(allProps.get("sdClaims") instanceof Map<?, ?> rawSdClaims)) {
                return credentialJwt + "~";
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> sdClaimsMap = (Map<String, Object>) rawSdClaims;
            Set<String> normalizedPaths = selectedPaths.stream()
                    .map(this::normalizeSdClaimPath)
                    .collect(Collectors.toCollection(LinkedHashSet::new));
            // Collect disclosure blobs for the selected paths (preserving order, deduplicating)
            Set<String> disclosures = new LinkedHashSet<>();
            for (String path : normalizedPaths) {
                Object disc = resolveSdClaimDisclosures(sdClaimsMap, path);
                int before = disclosures.size();
                addDisclosureStrings(disclosures, disc);
                if (disclosures.size() == before) {
                    log.warn("No SD-JWT disclosures found for credential {} path '{}' (available keys: {})",
                            credential.getId(), path, sdClaimsMap.keySet());
                }
            }
            log.info("SD-JWT filtering for credential {}: selectedPaths={}, disclosuresIncluded={}",
                    credential.getId(), normalizedPaths, disclosures.size());
            // Reconstruct: credentialJwt ~ disc1 ~ disc2 ~ (trailing ~ required by SD-JWT)
            StringBuilder sb = new StringBuilder(credentialJwt);
            for (String disc : disclosures) {
                sb.append("~").append(disc);
            }
            sb.append("~");
            return sb.toString();
        } catch (Exception e) {
            log.warn("SD-JWT filtering failed for credential {}: {}", credential.getId(), e.getMessage());
            return credentialJwt + "~";
        }
    }

    private String normalizeSdClaimPath(String path) {
        if (path == null) {
            return "";
        }
        String normalized = path.startsWith("$.") ? path.substring(2) : path;
        return normalized.replaceFirst("^credentialSubject(\\[\\d+\\])?\\.", "");
    }

    /**
     * Resolves disclosure blobs for a UI claim path. Matching returns paths like {@code $.dateOfBirth}
     * while the SD-JWT handler may store keys as {@code credentialSubject.dateOfBirth} or
     * {@code credentialSubject[0].dateOfBirth}.
     */
    private Object resolveSdClaimDisclosures(Map<String, Object> sdClaimsMap, String normalizedPath) {
        String targetPath = normalizeSdClaimPath(normalizedPath);
        for (Map.Entry<String, Object> entry : sdClaimsMap.entrySet()) {
            if (sdClaimPathMatches(entry.getKey(), targetPath)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private boolean sdClaimPathMatches(String mapKey, String normalizedPath) {
        if (mapKey == null || normalizedPath == null) {
            return false;
        }
        return normalizeSdClaimPath(mapKey).equals(normalizedPath);
    }

    private void addDisclosureStrings(Set<String> disclosures, Object disc) {
        if (disc instanceof List<?> list) {
            list.forEach(d -> {
                if (d != null) {
                    disclosures.add(d.toString());
                }
            });
        } else if (disc instanceof String s && !s.isBlank()) {
            disclosures.add(s);
        }
    }

    /**
     * Maps format string to FormatType enum.
     */
    private FormatType mapToFormatType(String format) {
        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(format)) {
            return FormatType.LDP_VC;
        }
        if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(format)) {
            return FormatType.VC_SD_JWT;
        }
        if (CredentialFormat.DC_SD_JWT.getFormat().equalsIgnoreCase(format)) {
            return FormatType.DC_SD_JWT;
        }
        throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                "Unsupported credential format: " + format);
    }

    /**
     * Fetches selected credentials from the session cache.
     * Every requested credential ID must exist in the session (fail-fast, same as DCQL submit).
     */
    private List<DecryptedCredentialDTO> fetchSelectedCredentials(
            VerifiablePresentationSessionData sessionData, List<String> selectedCredentialIds) {
        if (sessionData == null || sessionData.getMatchingCredentials() == null) {
            throw new IllegalStateException("No matching credentials in session — call GET /credentials first");
        }
        Map<String, DecryptedCredentialDTO> cache = sessionData.getMatchingCredentials().stream()
                .collect(Collectors.toMap(DecryptedCredentialDTO::getId, dto -> dto, (a, b) -> a));

        List<DecryptedCredentialDTO> result = new ArrayList<>();
        for (String id : selectedCredentialIds) {
            DecryptedCredentialDTO dto = cache.get(id);
            if (dto == null) {
                throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                        "Selected credential not found in session: " + id);
            }
            result.add(dto);
        }
        return result;
    }

    /**
     * Validates all input parameters for presentation submission.
     */
    private void validateSubmissionRequest(SubmitPresentationRequestDTO request) {
        if (request == null) {
            throw new java.lang.IllegalArgumentException("Request cannot be null");
        }
        if (request.getSelectedCredentials() == null || request.getSelectedCredentials().isEmpty()) {
            throw new java.lang.IllegalArgumentException("Selected credentials cannot be null or empty");
        }
    }

    /**
     * Creates a VerifiablePresentationVerifierDTO from the authorization request.
     */
    private VerifiablePresentationVerifierDTO createVPResponseVerifierDTO(
            List<Verifier> preRegisteredVerifiers, AuthorizationRequest authorizationRequest, String walletId) {
        boolean preRegistered = preRegisteredVerifiers.stream()
                .map(Verifier::getClientId).anyMatch(id -> id.equals(authorizationRequest.getClientId()));
        boolean trusted = verifierService.isVerifierTrustedByWallet(authorizationRequest.getClientId(), walletId);
        String clientName = resolveClientName(authorizationRequest);
        String logo = resolveLogoUri(authorizationRequest);
        return new VerifiablePresentationVerifierDTO(
                authorizationRequest.getClientId(), clientName, logo, trusted, preRegistered,
                authorizationRequest.getRedirectUri());
    }

    private String resolveClientName(AuthorizationRequest authorizationRequest) {
        if (authorizationRequest instanceof AuthorizationDcqlRequest dcqlRequest) {
            return Optional.ofNullable(dcqlRequest.getClientMetadata())
                    .map(ClientMetadata::getClientName).filter(n -> !n.isBlank())
                    .orElse(authorizationRequest.getClientId());
        }
        if (authorizationRequest instanceof AuthorizationPresentationExchangeRequest peRequest) {
            return Optional.ofNullable(peRequest.getClientMetadata())
                    .map(ClientMetadataDraft23::getClientName).filter(n -> !n.isBlank())
                    .orElse(authorizationRequest.getClientId());
        }
        return authorizationRequest.getClientId();
    }

    private String resolveLogoUri(AuthorizationRequest authorizationRequest) {
        if (authorizationRequest instanceof AuthorizationDcqlRequest dcqlRequest) {
            return Optional.ofNullable(dcqlRequest.getClientMetadata())
                    .map(ClientMetadata::getLogoUri).orElse(null);
        }
        if (authorizationRequest instanceof AuthorizationPresentationExchangeRequest peRequest) {
            return Optional.ofNullable(peRequest.getClientMetadata())
                    .map(ClientMetadataDraft23::getLogoUri).orElse(null);
        }
        return null;
    }

    /**
     * Handles verifier rejection with error details.
     */
    private ResponseEntity<SubmitPresentationResponseDTO> handleVerifierRejection(
            String walletId, VerifiablePresentationSessionData vpSessionData, SubmitPresentationRequestDTO request)
            throws VPErrorNotSentException {
        // Create ErrorDTO from the request
        ErrorDTO payload = new ErrorDTO();
        payload.setErrorCode(request.getErrorCode());
        payload.setErrorMessage(request.getErrorMessage());
        return ResponseEntity.ok(rejectVerifier(walletId, vpSessionData, payload));
    }

    /**
     * Rejects the verifier by sending error information.
     */
    private SubmitPresentationResponseDTO rejectVerifier(
            String walletId, VerifiablePresentationSessionData vpSessionData, ErrorDTO payload)
            throws VPErrorNotSentException {
        try {
            VerifierResponse verifierResponse = openID4VPService.sendErrorToVerifier(vpSessionData, payload);
            SubmitPresentationResponseDTO result = new SubmitPresentationResponseDTO();
            result.setStatus(REJECTED_VERIFIER.getErrorCode());
            result.setMessage(REJECTED_VERIFIER.getErrorMessage());
            result.setRedirectUri(verifierResponse.getRedirectUri());
            return result;
        } catch (ApiNotAccessibleException | IOException | URISyntaxException | java.lang.IllegalArgumentException e) {
            throw new VPErrorNotSentException("Failed to send rejection to verifier — " + e.getMessage());
        }
    }

    /**
     * Stores presentation record in the database.
     */
    private void storePresentationRecord(
            String walletId, String presentationId, SubmitPresentationRequestDTO request,
            VerifiablePresentationSessionData sessionData, boolean success, LocalDateTime requestedAt) {
        try {
            if (sessionData == null) {
                return;
            }
            // Extract verifier information from session data
            VerifiablePresentation presentation = VerifiablePresentation.builder()
                    .id(presentationId)
                    .walletId(walletId)
                    .authRequest(extractVerifierAuthRequest(sessionData))
                    .presentationData(buildPresentationDataJson(request))
                    .verifierId(extractVerifierId(sessionData))
                    .status(success ? OpenID4VPConstants.STATUS_SUCCESS : OpenID4VPConstants.STATUS_ERROR)
                    .requestedAt(requestedAt)
                    .consent(true)
                    .build();
            // Save to database
            verifiablePresentationsRepository.save(presentation);
        } catch (Exception e) {
            log.error("Failed to store presentation record for presentationId={}", presentationId, e);
        }
    }

    /**
     * Creates presentation data JSON with selected credentials and SD claim selections.
     */
    private String buildPresentationDataJson(SubmitPresentationRequestDTO request) throws JsonProcessingException {
        Map<String, Object> presentationData = new LinkedHashMap<>();
        presentationData.put(OpenID4VPConstants.SELECTED_CREDENTIALS, request.getSelectedCredentials());
        Map<String, List<String>> selectedSdClaims = request.resolveEffectiveSelectedSdClaims();
        if (selectedSdClaims != null) {
            presentationData.put(OpenID4VPConstants.SELECTED_SD_CLAIMS, selectedSdClaims);
        }
        return objectMapper.writeValueAsString(presentationData);
    }

    /**
     * Extracts verifier ID from session data.
     */
    private String extractVerifierId(VerifiablePresentationSessionData sessionData) {
        try {
            // Since authorizationRequest is a URL, extract client_id from URL parameters
            if (sessionData.getAuthorizationRequest() != null) {
                return UrlParameterUtils.extractQueryParameter(
                        sessionData.getAuthorizationRequest(), OpenID4VPConstants.CLIENT_ID_PARAM);
            }
        } catch (Exception e) {
            log.warn("Failed to extract verifier ID", e);
        }
        return UNKNOWN_VERIFIER;
    }

    /**
     * Extracts verifier authorization request as JSON.
     */
    private String extractVerifierAuthRequest(VerifiablePresentationSessionData sessionData) {
        try {
            if (sessionData.getAuthorizationRequest() != null) {
                // Convert the URL string to a JSON object
                return objectMapper.writeValueAsString(Map.of(
                        OpenID4VPConstants.AUTHORIZATION_REQUEST_URL, sessionData.getAuthorizationRequest()));
            }
        } catch (Exception e) {
            log.warn("Failed to extract verifier auth request", e);
        }
        return EMPTY_JSON;
    }
}
