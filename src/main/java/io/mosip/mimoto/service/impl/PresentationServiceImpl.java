package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponseProof;
import io.mosip.mimoto.dto.openid.presentation.*;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.openID4VP.constants.SpecVersion;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static io.mosip.mimoto.util.JwtUtils.extractJwtPayloadFromSdJwt;
import static io.mosip.mimoto.util.JwtUtils.parseJwtHeader;

@Slf4j
@Service
public class PresentationServiceImpl implements PresentationService {

    private final DataShareServiceImpl dataShareService;

    private final ObjectMapper objectMapper;

    private final RestApiClient restApiClient;

    private final String injiOvpRedirectURLPattern;

    private final Integer maximumResponseHeaderSize;

    private final String dcqlRedirectURLPattern;

    public PresentationServiceImpl(
            DataShareServiceImpl dataShareService,
            ObjectMapper objectMapper,
            RestApiClient restApiClient,
            @Value("${mosip.inji.ovp.redirect.url.pattern}") String injiOvpRedirectURLPattern,
            @Value("${mosip.inji.ovp.dcql.redirect.url.pattern:%s#vp_token=%s}") String dcqlRedirectURLPattern,
            @Value("${server.tomcat.max-http-response-header-size:65536}") Integer maximumResponseHeaderSize
    ) {
        this.dataShareService = dataShareService;
        this.objectMapper = objectMapper;
        this.restApiClient = restApiClient;
        this.injiOvpRedirectURLPattern = injiOvpRedirectURLPattern;
        this.dcqlRedirectURLPattern = dcqlRedirectURLPattern;
        this.maximumResponseHeaderSize = maximumResponseHeaderSize;
    }


    @Override
    public String processVPRequest(PresentationRequestDTO presentationRequestDTO, SpecVersion specVersion) throws IOException {
        log.info("Processing VP request with spec_version: {}", specVersion);

        if (SpecVersion.DRAFT_23 == specVersion) {
            if (presentationRequestDTO.getPresentationDefinition() == null) {
                throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
            }
            return authorizePresentation(presentationRequestDTO);
        }
        if (SpecVersion.V1 == specVersion) {
            if (presentationRequestDTO.getDcqlQuery() == null || presentationRequestDTO.getDcqlQuery().isBlank()) {
                throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
            }
            return authorizeDcqlPresentation(presentationRequestDTO);
        }

        log.error("Unsupported OpenID4VP spec_version: {}", specVersion);
        throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
    }

    private String authorizePresentation(PresentationRequestDTO presentationRequestDTO) throws IOException {
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



    /**
     * DCQL authorize flow — builds OVP 1.0 vp_token map { queryId: [presentation] }
     */
    private String authorizeDcqlPresentation(PresentationRequestDTO presentationRequestDTO) throws IOException {
        VCCredentialResponse vcCredentialResponse = dataShareService.downloadCredentialFromDataShare(presentationRequestDTO);
        String format = vcCredentialResponse.getFormat();
        if (format == null || format.isBlank()) {
            log.error("DCQL: downloaded credential has no format");
            throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
        }

        log.info("DCQL authorize: building presentation for format={}", format);

        Map<String, Object> dcqlQueryMap = parseDcqlQueryMap(presentationRequestDTO.getDcqlQuery());
        List<Map<String, Object>> credentials = extractDcqlCredentialQueries(dcqlQueryMap);

        Map<String, Object> matchingQuery = credentials.stream()
                .filter(cred -> {
                    Object queryFormat = cred.get("format");
                    return queryFormat instanceof String s && format.equalsIgnoreCase(s);
                })
                .findFirst()
                .orElse(null);
        if (matchingQuery == null) {
            log.error("DCQL: no credential query matches VC format {}", format);
            throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
        }

        Object queryIdObj = matchingQuery.get("id");
        if (!(queryIdObj instanceof String queryId) || queryId.isBlank()) {
            throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
        }

        // Data Share Online Sharing always uses require_cryptographic_holder_binding=false
        // (no holder key). Inji Verify then expects:
        //   LDP  -> plain VerifiableCredential (not unbound VP)
        //   SD-JWT -> credential string without KB-JWT
        Object presentation;
        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(format)) {
            presentation = objectMapper.convertValue(
                    vcCredentialResponse.getCredential(), VCCredentialProperties.class);
        } else if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(format)
                || CredentialFormat.DC_SD_JWT.getFormat().equalsIgnoreCase(format)) {
            presentation = objectMapper.convertValue(vcCredentialResponse.getCredential(), String.class);
        } else {
            throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
        }

        // OVP 1.0 / DCQL vp_token: { "<query_id>": [ presentation ] }
        Map<String, Object> vpTokenMap = new LinkedHashMap<>();
        vpTokenMap.put(queryId, List.of(presentation));
        String vpToken = objectMapper.writeValueAsString(vpTokenMap);

        if (presentationRequestDTO.getResponseMode() != null
                && "direct_post".equals(presentationRequestDTO.getResponseMode())) {
            return postVpToResponseUri(
                    presentationRequestDTO.getResponseUri(),
                    presentationRequestDTO.getRedirectUri(),
                    vpToken,
                    null,
                    presentationRequestDTO.getState(),
                    SpecVersion.V1);
        }

        String redirectString = buildDcqlRedirectString(vpToken, presentationRequestDTO.getRedirectUri());
        if (redirectString.length() > maximumResponseHeaderSize) {
            throw new VPNotCreatedException(ErrorConstants.URI_TOO_LONG.getErrorCode(), ErrorConstants.URI_TOO_LONG.getErrorMessage());
        }
        return redirectString;
    }

    private Map<String, Object> parseDcqlQueryMap(String dcqlQuery) {
        try {
            Map<String, Object> dcqlQueryMap = objectMapper.readValue(dcqlQuery, new TypeReference<Map<String, Object>>() {});
            if (dcqlQueryMap == null) {
                throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
            }
            return dcqlQueryMap;
        } catch (JsonProcessingException e) {
            log.error("DCQL: failed to parse dcql_query JSON: {}", e.getMessage(), e);
            throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> extractDcqlCredentialQueries(Map<String, Object> dcqlQueryMap) {
        Object credentialsObj = dcqlQueryMap.get("credentials");
        if (!(credentialsObj instanceof List<?> credentialsList) || credentialsList.isEmpty()) {
            throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
        }

        List<Map<String, Object>> credentials = new ArrayList<>(credentialsList.size());
        for (Object item : credentialsList) {
            if (!(item instanceof Map<?, ?> rawMap)) {
                throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
            }
            for (Object key : rawMap.keySet()) {
                if (!(key instanceof String)) {
                    throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
                }
            }
            credentials.add((Map<String, Object>) rawMap);
        }
        return credentials;
    }

    private String buildDcqlRedirectString(String vpToken, String redirectUri) {
        // Fallback when response_mode is not direct_post. Pattern is validated at startup to keep
        // vp_token in the URL fragment (not query), limiting server/proxy log exposure.
        return String.format(dcqlRedirectURLPattern,
                redirectUri,
                URLEncoder.encode(vpToken, StandardCharsets.UTF_8));
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

    /**
     * Builds a minimal DCQL query for Data Share Online Sharing QR (mirrors PD depth: format + type/vct).
     * Used to smoke-test QR generation with both presentation_definition and dcql_query embedded.
     */
    public Map<String, Object> constructDcqlQuery(VCCredentialResponse vcRes) {
        String vcFormat = vcRes.getFormat();
        Map<String, Object> credentialQuery = new LinkedHashMap<>();
        credentialQuery.put("id", UUID.randomUUID().toString());
        credentialQuery.put("format", vcFormat);
        // Data Share Online Sharing cannot produce holder-bound presentations
        credentialQuery.put("require_cryptographic_holder_binding", false);

        Map<String, Object> meta = new LinkedHashMap<>();
        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(vcFormat)) {
            VCCredentialProperties ldp = objectMapper.convertValue(vcRes.getCredential(), VCCredentialProperties.class);
            List<String> types = ldp.getType();
            if (types != null && !types.isEmpty()) {
                meta.put("type_values", List.of(types));
            }
        } else if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(vcFormat)
                || CredentialFormat.DC_SD_JWT.getFormat().equalsIgnoreCase(vcFormat)) {
            Map<String, Object> jwtPayload = extractJwtPayloadFromSdJwt((String) vcRes.getCredential());
            Object vct = jwtPayload.get("vct");
            if (vct != null) {
                meta.put("vct_values", List.of(vct.toString()));
            } else {
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
                if (lastType != null) {
                    meta.put("vct_values", List.of(lastType));
                }
            }
        }
        if (!meta.isEmpty()) {
            credentialQuery.put("meta", meta);
        }

        Map<String, Object> dcqlQuery = new LinkedHashMap<>();
        dcqlQuery.put("credentials", List.of(credentialQuery));
        return dcqlQuery;
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
                    SpecVersion.DRAFT_23
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

    private String buildRedirectString(String vpToken, String redirectUri, String presentationSubmission) {
        return String.format(injiOvpRedirectURLPattern,
                redirectUri,
                Base64.getUrlEncoder().encodeToString(vpToken.getBytes(StandardCharsets.UTF_8)),
                URLEncoder.encode(presentationSubmission, StandardCharsets.UTF_8));
    }

    private String createVpToken(VerifiablePresentationDTO vpDTO) throws JsonProcessingException {
        return objectMapper.writeValueAsString(vpDTO);
    }

    private String postVpToResponseUri(String responseUri, String redirectUri, String vpToken,
                                       String presentationSubmission, String state, SpecVersion specVersion) {
        MultiValueMap<String, String> postRequest = new LinkedMultiValueMap<>();
        if (SpecVersion.V1 == specVersion) {
            // OVP 1.0 / DCQL: raw JSON map { queryId: [presentation] } — not Base64-encoded
            postRequest.add("vp_token", vpToken);
        } else if (SpecVersion.DRAFT_23 == specVersion) {
            postRequest.add("vp_token", Base64.getUrlEncoder().encodeToString(vpToken.getBytes(StandardCharsets.UTF_8)));
            if (presentationSubmission != null) {
                postRequest.add("presentation_submission", presentationSubmission);
            }
        } else {
            log.error("Unsupported OpenID4VP spec_version for direct_post: {}", specVersion);
            throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
        }

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

            log.info("Response from verifier after POST: {}", postResponse);

            // Check for redirect_uri in response first
            if (postResponse != null && postResponse.containsKey("redirect_uri")) {
                String responseRedirectUri = (String) postResponse.get("redirect_uri");
                if (responseRedirectUri != null && !responseRedirectUri.isEmpty()) {
                    return responseRedirectUri;
                }
            }

            // Use request's redirectUri if it's non-blank
            if (redirectUri != null && !redirectUri.isBlank()) {
                log.info("Using redirectUri from request: {}", redirectUri);
                return redirectUri;
            }

            // Fallback behavior if redirect_uri is not provided
            log.warn("No redirect_uri received from verifier in POST response. Falling back to response_uri.");
            return responseUri + "?status=vp_sent";

        } catch (VPNotCreatedException e) {
            throw e;
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

}