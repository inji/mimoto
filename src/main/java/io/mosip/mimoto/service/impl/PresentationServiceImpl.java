package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.SubmitPresentationResponseDTO;
import io.mosip.mimoto.dto.VerifiablePresentationResponseDTO;
import io.mosip.mimoto.dto.VerifiablePresentationVerifierDTO;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponseProof;
import io.mosip.mimoto.dto.openid.presentation.*;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.VPErrorNotSentException;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.openID4VP.verifier.VerifierResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.ErrorConstants.REJECTED_VERIFIER;
import static io.mosip.mimoto.util.JwtUtils.extractJwtPayloadFromSdJwt;
import static io.mosip.mimoto.util.JwtUtils.parseJwtHeader;

@Slf4j
@Service
public class PresentationServiceImpl implements PresentationService {

    @Autowired
    private DataShareServiceImpl dataShareService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RestApiClient restApiClient;

    @Autowired
    private VerifierService verifierService;

    @Autowired
    private OpenID4VPService openID4VPService;

    @Value("${mosip.inji.ovp.redirect.url.pattern}")
    private String injiOvpRedirectURLPattern;

    @Value("${server.tomcat.max-http-response-header-size:65536}")
    private Integer maximumResponseHeaderSize;

    @Override
    public VerifiablePresentationResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId) throws ApiNotAccessibleException, IOException, URISyntaxException {
        String presentationId = UUID.randomUUID().toString();

        //Initialize OpenID4VP instance with presentationId as traceability id for each new Verifiable Presentation request
        OpenID4VP openID4VP = openID4VPService.create(presentationId);

        List<Verifier> preRegisteredVerifiers = getPreRegisteredVerifiers();
        boolean shouldValidateClient = verifierService.isVerifierClientPreregistered(preRegisteredVerifiers, urlEncodedVPAuthorizationRequest);
        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest, preRegisteredVerifiers, shouldValidateClient);
        VerifiablePresentationVerifierDTO verifiablePresentationVerifierDTO = createVPResponseVerifierDTO(preRegisteredVerifiers, authorizationRequest, walletId);

        return new VerifiablePresentationResponseDTO(presentationId, verifiablePresentationVerifierDTO);
    }

    private VerifiablePresentationVerifierDTO createVPResponseVerifierDTO(List<Verifier> preRegisteredVerifiers, AuthorizationRequest authorizationRequest, String walletId) {

        boolean isVerifierPreRegisteredWithWallet = preRegisteredVerifiers.stream().map(
                Verifier::getClientId).toList().contains(authorizationRequest.getClientId());

        boolean isVerifierTrustedByWallet = verifierService.isVerifierTrustedByWallet(authorizationRequest.getClientId(), walletId);

        String clientName = Optional.ofNullable(authorizationRequest.getClientMetadata())
                .map(ClientMetadata::getClientName)
                .filter(name -> !name.isBlank())
                .orElse(authorizationRequest.getClientId());

        String logo = Optional.ofNullable(authorizationRequest.getClientMetadata())
                .map(ClientMetadata::getLogoUri)
                .orElse(null);

        return new VerifiablePresentationVerifierDTO(
                authorizationRequest.getClientId(),
                clientName,
                logo,
                isVerifierTrustedByWallet,
                isVerifierPreRegisteredWithWallet,
                authorizationRequest.getRedirectUri()
        );
    }

    private List<Verifier> getPreRegisteredVerifiers() throws ApiNotAccessibleException, IOException {

        return verifierService.getTrustedVerifiers().getVerifiers().stream()
                .map(verifierDTO -> new Verifier(verifierDTO.getClientId(), verifierDTO.getResponseUris(), verifierDTO.getJwksUri(), verifierDTO.getAllowUnsignedRequest()))
                .toList();
    }

    @Override
    public String authorizePresentation(PresentationRequestDTO presentationRequestDTO) throws IOException {
        VCCredentialResponse vcCredentialResponse = dataShareService.downloadCredentialFromDataShare(presentationRequestDTO);
        PresentationDefinitionDTO presentationDefinitionDTO = presentationRequestDTO.getPresentationDefinition();
        if (presentationDefinitionDTO == null) {
            throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
        }

        log.info("Started the Constructing VP Token");

        return presentationDefinitionDTO.getInputDescriptors()
                .stream()
                .findFirst()
                .map(inputDescriptorDTO -> {
                    try {
                        return processInputDescriptor(vcCredentialResponse, inputDescriptorDTO, presentationRequestDTO, presentationDefinitionDTO);
                    } catch (JsonProcessingException e) {
                        log.error("Exception occured during processInputDesciptor: {}", e.getMessage());
                        throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
                    }
                })
                .orElseThrow(() -> new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage()));
    }

    private String processInputDescriptor(VCCredentialResponse vcCredentialResponse, InputDescriptorDTO inputDescriptorDTO,
                                          PresentationRequestDTO presentationRequestDTO, PresentationDefinitionDTO presentationDefinitionDTO) throws JsonProcessingException {
        String format = vcCredentialResponse.getFormat();
        VerifiablePresentationDTO vpDTO;

        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(format)) {
            VCCredentialProperties ldpCredential = objectMapper.convertValue(vcCredentialResponse.getCredential(), VCCredentialProperties.class);
            if (inputDescriptorDTO.getFormat().get("ldpVc").get("proofTypes")
                    .stream().anyMatch(proofType -> ldpCredential.getProof().getType().equals(proofType))) {
                vpDTO = constructVerifiablePresentationString(ldpCredential);
            } else {
                throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
            }
        } else if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(format)
                || CredentialFormat.DC_SD_JWT.getFormat().equalsIgnoreCase(format)) {
            String credential = objectMapper.convertValue(vcCredentialResponse.getCredential(), String.class);
            Map<String, Object> jwtHeaders = parseJwtHeader(credential);
            String responseAlgo = (String) jwtHeaders.get("alg");
            if (inputDescriptorDTO.getFormat().get(format).get("sd-jwt_alg_values")
                    .stream().anyMatch(responseAlgo::equals)) {
                vpDTO = constructVerifiablePresentationStringForSDjwt(credential);
            } else {
                throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
            }
        } else {
            throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
        }

        // Create VP Token
        String vpToken = createVpToken(vpDTO);

        // Create PresentationSubmission
        String presentationSubmission = constructPresentationSubmission(format, vpDTO, presentationDefinitionDTO, inputDescriptorDTO);

        // If response_uri is present, POST the response
        if (presentationRequestDTO.getResponseMode() != null && "direct_post".equals(presentationRequestDTO.getResponseMode())) {
            return postVpToResponseUri(
                    presentationRequestDTO.getResponseUri(),
                    presentationRequestDTO.getRedirectUri(),
                    vpToken,
                    presentationSubmission,
                    presentationRequestDTO.getState(),
                    presentationRequestDTO.getNonce()
            );
        }

        // Otherwise, do redirect
        String redirectString = buildRedirectString(
                vpToken,
                presentationRequestDTO.getRedirectUri(),
                presentationSubmission
        );

        if (redirectString.length() > maximumResponseHeaderSize) {
            throw new VPNotCreatedException(ErrorConstants.URI_TOO_LONG.getErrorCode(), ErrorConstants.URI_TOO_LONG.getErrorMessage());
        }

        return redirectString;
    }

    private String createVpToken(VerifiablePresentationDTO vpDTO) throws JsonProcessingException {
        return objectMapper.writeValueAsString(vpDTO);
    }

    private String buildRedirectString(String vpToken, String redirectUri, String presentationSubmission) {
        return String.format(injiOvpRedirectURLPattern,
                redirectUri,
                Base64.getUrlEncoder().encodeToString(vpToken.getBytes(StandardCharsets.UTF_8)),
                URLEncoder.encode(presentationSubmission, StandardCharsets.UTF_8));
    }

    private String postVpToResponseUri(String responseUri, String redirectUri, String vpToken, String presentationSubmission, String state, String nonce) throws JsonProcessingException {
        MultiValueMap<String, String> postRequest = new LinkedMultiValueMap<>();
        postRequest.add("vp_token", Base64.getUrlEncoder().encodeToString(vpToken.getBytes(StandardCharsets.UTF_8)));
        postRequest.add("presentation_submission", presentationSubmission);

        if (state != null) {
            postRequest.add("state", state);
        }

        log.info("Posting VP to response_uri: {}", responseUri);
        try {
            Map<String, Object> postResponse = restApiClient.postApi(
                    responseUri,
                    MediaType.APPLICATION_FORM_URLENCODED,
                    postRequest,
                    Map.class
            );

            // Use request's redirectUri if it's non-blank
            if (redirectUri != null && !redirectUri.isBlank()) {
                log.info("Using redirectUri from request: {}", redirectUri);
                return redirectUri;
            }

            log.info("Response from verifier after POST: {}", postResponse);

            // Check for redirect_uri in response first
            if (postResponse != null && postResponse.containsKey("redirect_uri")) {
                String responseRedirectUri = (String) postResponse.get("redirect_uri");
                if (responseRedirectUri != null && !responseRedirectUri.isEmpty()) {
                    return responseRedirectUri;
                }
            }

            // Fallback behavior if redirect_uri is not provided
            log.warn("No redirect_uri received from verifier in POST response. Falling back to response_uri.");
            return responseUri + "?status=vp_sent";

        } catch (Exception e) {
            log.error("Exception while submitting the vp_token to the response_uri", e);
            throw new VPNotCreatedException(ErrorConstants.INTERNAL_SERVER_ERROR.getErrorCode(), ErrorConstants.INTERNAL_SERVER_ERROR.getErrorMessage());
        }
    }

    private VerifiablePresentationDTO constructVerifiablePresentationString(VCCredentialProperties vcCredentialProperties) {
        Object context = vcCredentialProperties.getContext();
        List<Object> contextList = (context instanceof List<?> list)
                ? (List<Object>) list
                : List.of(context);

        return VerifiablePresentationDTO.builder()
                .verifiableCredential(Collections.singletonList(vcCredentialProperties))
                .type(Collections.singletonList("VerifiablePresentation"))
                .context(contextList)
                .build();
    }

    private VerifiablePresentationDTO constructVerifiablePresentationStringForSDjwt(String vcCredential) {
        return VerifiablePresentationDTO.builder()
                .verifiableCredential(Collections.singletonList(vcCredential))
                .type(Collections.singletonList("VerifiablePresentation"))
                .build();
    }

    private String constructPresentationSubmission(String format, VerifiablePresentationDTO verifiablePresentationDTO, PresentationDefinitionDTO presentationDefinitionDTO, InputDescriptorDTO inputDescriptorDTO) throws JsonProcessingException {
        AtomicInteger atomicInteger = new AtomicInteger(0);
        List<SubmissionDescriptorDTO> submissionDescriptorDTOList = verifiablePresentationDTO.getVerifiableCredential()
                .stream().map(verifiableCredential -> SubmissionDescriptorDTO.builder()
                        .id(inputDescriptorDTO.getId())
                        .format(format)
                        .path("$.verifiableCredential[" + atomicInteger.getAndIncrement() + "]").build()).collect(Collectors.toList());

        PresentationSubmissionDTO presentationSubmissionDTO = PresentationSubmissionDTO.builder()
                .id(UUID.randomUUID().toString())
                .definition_id(presentationDefinitionDTO.getId())
                .descriptorMap(submissionDescriptorDTOList).build();
        return objectMapper.writeValueAsString(presentationSubmissionDTO);
    }

    public PresentationDefinitionDTO constructPresentationDefinition(VCCredentialResponse vcRes) {
        String vcFormat = vcRes.getFormat();
        List<InputDescriptorDTO> inputDescriptors = new ArrayList<>();

        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(vcFormat)) {
            VCCredentialProperties ldp = objectMapper.convertValue(vcRes.getCredential(), VCCredentialProperties.class);
            String lastType = ldp.getType().get(ldp.getType().size() - 1);
            String proofType = Optional.ofNullable(ldp.getProof()).map(VCCredentialResponseProof::getType).orElse(null);

            FieldDTO field = FieldDTO.builder()
                    .path(new String[]{"$.type"})
                    .filter(FilterDTO.builder().type("String").pattern(lastType).build())
                    .build();

            Map<String, Map<String, List<String>>> format = Map.of(
                    "ldpVc", Map.of("proofTypes", List.of(proofType))
            );

            inputDescriptors.add(InputDescriptorDTO.builder()
                    .id(UUID.randomUUID().toString())
                    .constraints(ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build())
                    .format(format)
                    .build());

        } else if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(vcFormat) || CredentialFormat.DC_SD_JWT.getFormat().equalsIgnoreCase(vcFormat)) {
            Map<String, Object> jwtPayload = extractJwtPayloadFromSdJwt((String) vcRes.getCredential());
            List<?> typeList = (List<?>) jwtPayload.get("type");
            String lastType = null;
            if (typeList != null && !typeList.isEmpty()) {
                Object lastItem = typeList.get(typeList.size() - 1);
                if (lastItem instanceof Map) {
                    Object value = ((Map<?, ?>) lastItem).get("_value");
                    lastType = value != null ? value.toString() : null;
                } else {
                    lastType = lastItem.toString();
                }
            }
            Map<String, Object> jwtHeaders = parseJwtHeader((String) vcRes.getCredential());
            String algo = (String) jwtHeaders.get("alg");

            FieldDTO field = FieldDTO.builder()
                    .path(new String[]{"$.type"})
                    .filter(FilterDTO.builder().type("String").pattern(lastType).build())
                    .build();
            Map<String, Map<String, List<String>>> format = Map.of(
                    vcRes.getFormat(), Map.of(
                            "sd-jwt_alg_values", List.of(algo)
                    )
            );
            inputDescriptors.add(InputDescriptorDTO.builder()
                    .id(UUID.randomUUID().toString())
                    .constraints(ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build())
                    .format(format)
                    .build());

        }
        return PresentationDefinitionDTO.builder()
                .id(UUID.randomUUID().toString())
                .inputDescriptors(inputDescriptors)
                .build();
    }

    @Override
    public SubmitPresentationResponseDTO rejectVerifier(String walletId, VerifiablePresentationSessionData vpSessionData, ErrorDTO payload) throws VPErrorNotSentException {
        try {
            VerifierResponse verifierResponse = openID4VPService.sendErrorToVerifier(vpSessionData, payload);
            log.info("Sent rejection to verifier. Response: {}", verifierResponse);

            SubmitPresentationResponseDTO submitPresentationResponseDTO = new SubmitPresentationResponseDTO();
            submitPresentationResponseDTO.setStatus(REJECTED_VERIFIER.getErrorCode());
            submitPresentationResponseDTO.setMessage(REJECTED_VERIFIER.getErrorMessage());
            submitPresentationResponseDTO.setRedirectUri(verifierResponse.getRedirectUri());
            return submitPresentationResponseDTO;
        } catch (ApiNotAccessibleException | IOException | URISyntaxException | IllegalArgumentException e ) {
            log.error("Failed to send rejection to verifier for walletId: {} - Error: {}", walletId, e.getMessage(), e);
            throw new VPErrorNotSentException("Failed to send rejection to verifier - " + e.getMessage());
        }
    }
}