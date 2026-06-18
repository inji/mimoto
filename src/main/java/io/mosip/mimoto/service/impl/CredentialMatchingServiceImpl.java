package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.constant.SpecVersion;
import io.mosip.mimoto.dto.CredentialDTO;
import io.mosip.mimoto.dto.CredentialSetInfo;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.mimoto.dto.DcqlQueryGroup;
import io.mosip.mimoto.dto.MatchingCredentialsDTO;
import io.mosip.mimoto.dto.MatchingCredentialsResponseDTO;
import io.mosip.mimoto.dto.mimoto.IssuerConfig;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.service.CredentialFormatHandlerFactory;
import io.mosip.mimoto.service.CredentialFormatHandler;
import io.mosip.mimoto.service.CredentialMatchingService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.JwtUtils;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.*;
import io.mosip.openID4VP.dcql.query.ClaimValue;
import io.mosip.openID4VP.dcql.query.ClaimsQuery;
import io.mosip.openID4VP.dcql.query.CredentialQuery;
import io.mosip.openID4VP.dcql.query.CredentialSetQuery;
import io.mosip.openID4VP.dcql.query.DCQLQuery;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;
import static io.mosip.mimoto.exception.ErrorConstants.UNSUPPORTED_FORMAT;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
@Service
public class CredentialMatchingServiceImpl implements CredentialMatchingService {

    private static final String JSON_PATH_PREFIX = "$.";
    private static final String LDP_VC_FORMAT = "ldp_vc";
    private static final String PROOF_TYPE_KEY = "proof_type";
    private static final String SD_JWT_ALG_VALUES_KEY = "sd-jwt_alg_values";
    private static final String CREDENTIAL_SUBJECT_PREFIX = "credentialSubject.";
    private static final String ALG = "alg";
    private static final String CREDENTIAL_SUBJECT = "credentialSubject";
    private static final String SD = "_sd";

    private final ObjectMapper objectMapper;

    private final IssuersService issuersService;

    private final OpenID4VPService openID4VPService;

    private final WalletCredentialService walletCredentialService;

    private final CredentialFormatHandlerFactory credentialFormatHandlerFactory;

    public CredentialMatchingServiceImpl(ObjectMapper objectMapper, IssuersService issuersService, OpenID4VPService openID4VPService, WalletCredentialService walletCredentialService, CredentialFormatHandlerFactory credentialFormatHandlerFactory) {
        this.objectMapper = objectMapper;
        this.issuersService = issuersService;
        this.openID4VPService = openID4VPService;
        this.walletCredentialService = walletCredentialService;
        this.credentialFormatHandlerFactory = credentialFormatHandlerFactory;
    }


    @Override
    public MatchingCredentialsDTO getMatchingCredentials(VerifiablePresentationSessionData sessionData, String walletId, String base64Key) throws ApiNotAccessibleException, IOException {
        log.info("Getting matching credentials with wallet data for walletId: {}, specVersion: {}",
                walletId, sessionData != null ? sessionData.getSpecVersion() : null);

        List<DecryptedCredentialDTO> decryptedCredentials = walletCredentialService.getDecryptedCredentials(walletId, base64Key);

        if (sessionData != null && SpecVersion.V1_0.equals(sessionData.getSpecVersion())) {
            return matchWithDcqlQuery(sessionData, walletId, decryptedCredentials);
        }
        return matchWithPresentationDefinition(sessionData, walletId, base64Key, decryptedCredentials);
    }

    private MatchingCredentialsDTO matchWithPresentationDefinition(
            VerifiablePresentationSessionData sessionData,
            String walletId,
            String base64Key,
            List<DecryptedCredentialDTO> decryptedCredentials) throws ApiNotAccessibleException, IOException {

        PresentationDefinition presentationDefinition = openID4VPService.resolvePresentationDefinition(
                sessionData.getPresentationId(), sessionData.getAuthorizationRequest(), sessionData.isVerifierClientPreregistered());

        validateInputParameters(presentationDefinition, walletId, base64Key);

        if (decryptedCredentials.isEmpty()) {
            MatchingCredentialsResponseDTO emptyResponse = createEmptyResponseWithMissingClaims(presentationDefinition);
            return MatchingCredentialsDTO.builder()
                    .matchingCredentialsResponse(emptyResponse)
                    .matchingCredentials(new ArrayList<>())
                    .build();
        }

        List<InputDescriptor> descriptors = presentationDefinition.getInputDescriptors();
        Map<Integer, List<CredentialDTO>> matchingCredentialsByDescriptor = new HashMap<>();
        Map<String, String> credentialToDescriptor = new HashMap<>();
        Set<String> missingClaims = new HashSet<>();

        IntStream.range(0, descriptors.size())
                .forEach(i -> {
                    InputDescriptor descriptor = descriptors.get(i);
                    List<DecryptedCredentialDTO> descriptorMatches = decryptedCredentials.stream()
                            .filter(decrypted -> matchesInputDescriptor(decrypted.getCredential(), descriptor))
                            .collect(Collectors.toList());

                    List<CredentialDTO> matches = descriptorMatches.stream()
                            .map(this::buildAvailableCredential)
                            .collect(Collectors.toList());

                    if (!matches.isEmpty()) {
                        descriptorMatches.forEach(dto -> credentialToDescriptor.put(dto.getId(), descriptor.getId()));
                        matchingCredentialsByDescriptor.put(i, matches);
                    } else {
                        boolean hasFormatMatch = decryptedCredentials.stream()
                                .anyMatch(decrypted -> matchesFormat(decrypted.getCredential(), descriptor.getFormat()));
                        if (hasFormatMatch) {
                            missingClaims.addAll(extractClaimsFromInputDescriptor(descriptor));
                        } else {
                            missingClaims.addAll(extractFormatConstraintKeys(descriptor));
                        }
                    }
                });

        Set<String> addedCredentialIds = new HashSet<>();
        List<CredentialDTO> availableCredentials = matchingCredentialsByDescriptor.values().stream()
                .flatMap(List::stream)
                .filter(credential -> addedCredentialIds.add(credential.getCredentialId()))
                .collect(Collectors.toList());

        MatchingCredentialsResponseDTO matchingCredentialsResponse = MatchingCredentialsResponseDTO.builder()
                .availableCredentials(availableCredentials)
                .missingClaims(missingClaims)
                .isDcql(false)
                .build();

        Set<String> matchedCredentialIds = availableCredentials.stream()
                .map(CredentialDTO::getCredentialId)
                .collect(Collectors.toSet());

        List<DecryptedCredentialDTO> matchingCredentials = decryptedCredentials.stream()
                .filter(credential -> matchedCredentialIds.contains(credential.getId()))
                .peek(credential -> credential.setDescriptorId(credentialToDescriptor.get(credential.getId())))
                .collect(Collectors.toList());

        return MatchingCredentialsDTO.builder()
                .matchingCredentialsResponse(matchingCredentialsResponse)
                .matchingCredentials(matchingCredentials)
                .build();
    }

    private MatchingCredentialsDTO matchWithDcqlQuery(
            VerifiablePresentationSessionData sessionData,
            String walletId,
            List<DecryptedCredentialDTO> decryptedCredentials) throws ApiNotAccessibleException, IOException {

        if (walletId == null || walletId.trim().isEmpty()) {
            throw new IllegalArgumentException("Wallet ID cannot be null or empty");
        }

        DCQLQuery dcqlQuery = openID4VPService.resolveDcqlQuery(
                sessionData.getPresentationId(),
                sessionData.getAuthorizationRequest(),
                sessionData.isVerifierClientPreregistered());

        if (dcqlQuery == null) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                    "Authorization request does not contain a DCQL query");
        }

        List<DcqlQueryGroup> queryGroups = new ArrayList<>();
        Map<String, DecryptedCredentialDTO> matchedById = new LinkedHashMap<>();

        for (CredentialQuery credentialQuery : dcqlQuery.getCredentials()) {
            List<DecryptedCredentialDTO> matches = decryptedCredentials.stream()
                    .filter(dto -> matchesDcqlQuery(dto.getCredential(), credentialQuery))
                    .collect(Collectors.toList());

            matches.forEach(dto -> {
                dto.setDescriptorId(credentialQuery.getId());
                matchedById.putIfAbsent(dto.getId(), dto);
            });

            Set<String> missingClaims = matches.isEmpty()
                    ? extractMissingClaimsFromQuery(credentialQuery)
                    : Collections.emptySet();

            List<CredentialDTO> credentialDTOs = matches.stream()
                    .map(this::buildAvailableCredential)
                    .collect(Collectors.toList());

            queryGroups.add(DcqlQueryGroup.builder()
                    .queryId(credentialQuery.getId())
                    .required(true)
                    .multiple(credentialQuery.getMultiple())
                    .availableCredentials(credentialDTOs)
                    .missingClaims(missingClaims)
                    .build());
        }

        List<CredentialSetInfo> credentialSets = new ArrayList<>();
        if (dcqlQuery.getCredentialSets() != null) {
            for (CredentialSetQuery cs : dcqlQuery.getCredentialSets()) {
                credentialSets.add(CredentialSetInfo.builder()
                        .required(cs.getRequired())
                        .options(cs.getOptions())
                        .build());
            }
        }

        log.info("matchWithDcqlQuery: walletId={}, queries={}, credentialSets={}, totalMatched={}",
                walletId, queryGroups.size(), credentialSets.size(), matchedById.size());

        MatchingCredentialsResponseDTO matchingCredentialsResponse = MatchingCredentialsResponseDTO.builder()
                .queryGroups(queryGroups)
                .credentialSets(credentialSets)
                .isDcql(true)
                .build();

        return MatchingCredentialsDTO.builder()
                .matchingCredentialsResponse(matchingCredentialsResponse)
                .matchingCredentials(new ArrayList<>(matchedById.values()))
                .build();
    }

    private boolean matchesDcqlQuery(VCCredentialResponse vc, CredentialQuery credentialQuery) {
        String queryFormat = credentialQuery.getFormat();
        String vcFormat = vc.getFormat();
        if (!queryFormat.equalsIgnoreCase(vcFormat)
                && !(CredentialFormat.isSdJwt(queryFormat) && CredentialFormat.isSdJwt(vcFormat))) {
            return false;
        }

        if (credentialQuery.getClaims() != null) {
            return credentialQuery.getClaims().stream()
                    .allMatch(claimQuery -> matchesDcqlClaimPath(vc, claimQuery));
        }
        return true;
    }

    private boolean matchesDcqlClaimPath(VCCredentialResponse vc, ClaimsQuery claimQuery) {
        if (claimQuery.getPath() == null || claimQuery.getPath().isEmpty()) {
            return true;
        }

        String jsonPath = JSON_PATH_PREFIX + claimQuery.getPath().stream()
                .map(Object::toString)
                .collect(Collectors.joining("."));

        Object credentialData = getCredentialData(vc);
        List<Object> found = evaluateJsonPath(jsonPath, credentialData);
        if (found.isEmpty()) {
            return false;
        }

        if (claimQuery.getValues() != null && !claimQuery.getValues().isEmpty()) {
            return claimQuery.getValues().stream()
                    .anyMatch(expected -> found.stream().anyMatch(actual -> dcqlValueMatches(actual, expected)));
        }
        return true;
    }

    private boolean dcqlValueMatches(Object actual, ClaimValue expected) {
        if (expected instanceof ClaimValue.StringValue sv) {
            return sv.getValue().equals(actual.toString());
        }
        if (expected instanceof ClaimValue.LongValue lv) {
            if (actual instanceof Number number) {
                return lv.getValue() == number.longValue();
            }
            return false;
        }
        if (expected instanceof ClaimValue.BoolValue bv) {
            if (actual instanceof Boolean bool) {
                return bv.getValue() == bool;
            }
            return false;
        }
        return false;
    }

    private Set<String> extractMissingClaimsFromQuery(CredentialQuery credentialQuery) {
        if (credentialQuery.getClaims() == null) {
            return Collections.emptySet();
        }
        return credentialQuery.getClaims().stream()
                .filter(cq -> cq.getPath() != null && !cq.getPath().isEmpty())
                .map(cq -> cq.getPath().stream().map(Object::toString).collect(Collectors.joining(".")))
                .collect(Collectors.toSet());
    }

    private void validateInputParameters(PresentationDefinition presentationDefinition, String walletId, String base64Key) throws IllegalArgumentException {
        if (walletId == null || walletId.trim().isEmpty()) {
            throw new IllegalArgumentException("Wallet ID cannot be null or empty");
        }

        if (base64Key == null || base64Key.trim().isEmpty()) {
            throw new IllegalArgumentException("Base64 key cannot be null or empty");
        }

        if (presentationDefinition == null) {
            throw new IllegalArgumentException("Presentation definition cannot be null");
        }

        if (presentationDefinition.getInputDescriptors().isEmpty()) {
            throw new IllegalArgumentException("Presentation definition must contain at least one input descriptor");
        }

        IntStream.range(0, presentationDefinition.getInputDescriptors().size())
                .filter(i -> {
                    InputDescriptor descriptor = presentationDefinition.getInputDescriptors().get(i);
                    return descriptor.getId().trim().isEmpty();
                })
                .findFirst()
                .ifPresent(i -> { throw new IllegalArgumentException("Input descriptor at index " + i + " must have a valid ID"); });
    }

    private MatchingCredentialsResponseDTO createEmptyResponseWithMissingClaims(PresentationDefinition presentationDefinition) {
        log.info("No credentials found for wallet");
        Set<String> missingClaims = presentationDefinition.getInputDescriptors().stream()
                .flatMap(descriptor -> extractFormatConstraintKeys(descriptor).stream())
                .collect(Collectors.toSet());
        return MatchingCredentialsResponseDTO.builder()
                .availableCredentials(Collections.emptyList())
                .missingClaims(missingClaims)
                .build();
    }

    private List<String> extractClaimsFromInputDescriptor(InputDescriptor inputDescriptor) {
        return extractClaimsFromFields(inputDescriptor.getConstraints().getFields(), false);
    }

    /**
     * Common method to extract claims from an array of fields.
     *
     * @param fields      List of Fields objects to extract claims from
     * @param deduplicate Whether to deduplicate claims using LinkedHashSet
     * @return List of extracted claim keys
     */
    private List<String> extractClaimsFromFields(List<Fields> fields, boolean deduplicate) {
        if (fields == null) {
            return Collections.emptyList();
        }

        Stream<String> claimsStream = fields.stream()
                .filter(Objects::nonNull)
                .filter(field -> !field.getPath().isEmpty())
                .flatMap(field -> field.getPath().stream())
                .map(this::extractClaimKeyFromPath)
                .filter(Objects::nonNull)
                .filter(claim -> !claim.isBlank());

        if (deduplicate) {
            return claimsStream.distinct().collect(Collectors.toList());
        } else {
            return claimsStream.collect(Collectors.toList());
        }
    }

    private boolean matchesInputDescriptor(VCCredentialResponse vc, InputDescriptor inputDescriptor) {
        Map<String, Map<String, List<String>>> formatToCheck = inputDescriptor.getFormat();

        if (!matchesFormat(vc, formatToCheck)) {
            return false;
        }

        if (inputDescriptor.getConstraints().getFields() != null) {
            return matchesConstraints(vc, inputDescriptor.getConstraints());
        }
        return true;
    }

    private boolean matchesFormat(VCCredentialResponse vc, Map<String, Map<String, List<String>>> descriptorFormat) {
        if (descriptorFormat == null) {
            return true;
        }

        String vcFormat = vc.getFormat();

        if (CredentialFormat.isSdJwt(vcFormat) && descriptorFormat.containsKey(vcFormat.toLowerCase())) {
            return matchesSdJwtAlgorithm(vc, descriptorFormat, vcFormat.toLowerCase());
        }
        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(vcFormat) && descriptorFormat.containsKey(LDP_VC_FORMAT)) {
            return matchesLdpVcFormat(vc, descriptorFormat);
        }
        return false;
    }

    private boolean matchesLdpVcFormat(VCCredentialResponse vc, Map<String, Map<String, List<String>>> descriptorFormat) {
        Map<String, List<String>> ldpVcFormat = descriptorFormat.get(LDP_VC_FORMAT);

        if (ldpVcFormat == null) {
            return false;
        }

        if (!ldpVcFormat.containsKey(PROOF_TYPE_KEY)) {
            return false;
        }

        VCCredentialProperties ldpCredential = objectMapper.convertValue(vc.getCredential(), VCCredentialProperties.class);
        String vcProofType = ldpCredential.getProof() != null ? ldpCredential.getProof().getType() : null;
        List<String> requiredProofTypes = ldpVcFormat.get(PROOF_TYPE_KEY);

        if (requiredProofTypes == null || requiredProofTypes.isEmpty()) {
            return true;
        }

        return vcProofType != null && requiredProofTypes.contains(vcProofType);
    }

    private boolean matchesSdJwtAlgorithm(VCCredentialResponse vc, Map<String, Map<String, List<String>>> requestFormat, String formatKey) {
        if (vc.getCredential() == null || !(vc.getCredential() instanceof String sdJwtString)) {
            return false;
        }

        Map<String, List<String>> sdJwtFormat = requestFormat.get(formatKey);
        List<?> requestAlgorithms = sdJwtFormat.get(SD_JWT_ALG_VALUES_KEY);
        if (requestAlgorithms != null) {
            return requestAlgorithms.contains(extractSdJwtAlgorithm(sdJwtString));
        }
        return true; // No sd-jwt_alg_values constraint → any algorithm is acceptable
    }

    private String extractSdJwtAlgorithm(String sdJwtString) {
        if (sdJwtString == null || sdJwtString.trim().isEmpty()) {
            return null;
        }
        try {
            Map<String, Object> header = JwtUtils.parseJwtHeader(sdJwtString);
            return (String) header.get(ALG);
        } catch (Exception e) {
            log.warn("Failed to extract algorithm from SD-JWT header", e);
            return null;
        }
    }

    private boolean matchesConstraints(VCCredentialResponse vc, Constraints constraints) {
        if (constraints.getFields() == null) {
            return true;
        }

        return constraints.getFields().stream().allMatch(field -> {
            if (field.getPath().isEmpty()) {
                return true;
            }
            return field.getPath().stream().anyMatch(path -> matchesFieldPath(vc, path, field.getFilter()));
        });
    }

    private boolean matchesFieldPath(VCCredentialResponse vc, String path, Filter filter) {
        Object credentialData = getCredentialData(vc);

        List<Object> matches = evaluateJsonPath(path, credentialData);

        if (matches.isEmpty()) {
            return false;
        }

        return matches.stream().anyMatch(match -> matchesFilter(match, filter));
    }

    private Object getCredentialData(VCCredentialResponse vc) {
        String format = vc.getFormat();
        CredentialFormatHandler credentialFormatHandler = credentialFormatHandlerFactory.getHandler(vc.getFormat());

        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(format)) {
            return credentialFormatHandler.extractAllCredentialProperties(vc);
        } else if (CredentialFormat.isSdJwt(format)) {
            Map<String, ?> extractedMap = credentialFormatHandler.extractAllCredentialProperties(vc);
            if (extractedMap == null) {
                return Collections.emptyMap();
            }
            Map<String, Object> credentialClaimsMap = new HashMap<>();
            // publicClaims and sdClaims are mutually exclusive by SD-JWT spec — no key collision.
            // sdClaims values are disclosure blobs (List<String>), not decoded claim values.
            // This supports existence-based field matching (e.g. $.given_name present).
            // Value-filter matching on SD claims (e.g. $.age >= 18) is not supported here
            // and requires decoding disclosures — tracked as a follow-up improvement.
            for (Map.Entry<String, ?> outer : extractedMap.entrySet()) {
                if (outer.getValue() instanceof Map<?, ?> innerMap) {
                    for (Map.Entry<?, ?> inner : innerMap.entrySet()) {
                        if (inner.getKey() instanceof String key) {
                            credentialClaimsMap.put(key, inner.getValue());
                        }
                    }
                }
            }
            return credentialClaimsMap;
        } else {
            throw new InvalidRequestException(UNSUPPORTED_FORMAT.getErrorCode(), "Unsupported credential format: " + format);
        }
    }

    private boolean matchesFilter(Object match, Filter filter) {
        if (filter == null) {
            return true;
        }

        String matchValue = match.toString();
        return matchValue.contains(filter.getPattern());

    }

    private List<Object> evaluateJsonPath(String path, Object json) {
        if (path == null || path.trim().isEmpty()) {
            return Collections.emptyList();
        }

        if (!path.startsWith(JSON_PATH_PREFIX)) {
            return Collections.emptyList();
        }

        if (json == null) {
            return Collections.emptyList();
        }

        try {
            Object result = JsonPath.read(json, path);

            if (result == null) {
                return Collections.emptyList();
            }

            if (result instanceof List) {
                return (List<Object>) result;
            }

            return Collections.singletonList(result);

        } catch (PathNotFoundException e) {
            log.debug("Path not found in JSON: {}", path);
            return Collections.emptyList();
        }
    }

    private List<String> extractRequiredClaims(PresentationDefinition presentationDefinition) {

        List<Fields> allFields = presentationDefinition.getInputDescriptors().stream()
                .filter(id -> id.getConstraints().getFields() != null)
                .flatMap(id -> id.getConstraints().getFields().stream())
                .collect(Collectors.toList());

        return extractClaimsFromFields(allFields, true);
    }

    private String extractClaimKeyFromPath(String path) {
        if (path == null || path.isBlank()) {
            return null;
        }
        int lastDot = path.lastIndexOf('.');
        String tail = lastDot >= 0 ? path.substring(lastDot + 1) : path;
        if (tail.startsWith("$")) {
            tail = tail.substring(1);
        }
        return tail;
    }

    private CredentialDTO buildAvailableCredential(DecryptedCredentialDTO decryptedCredentialDTO) {
        String issuerId = decryptedCredentialDTO.getCredentialMetadata().getIssuerId();
        String credentialType = decryptedCredentialDTO.getCredentialMetadata().getCredentialType();

        String credentialTypeDisplayName = "Unknown Credential";
        String credentialTypeLogo = null;
        Map<String, Object> publicClaimsMap;
        Map<String, Object> sdClaimsMap;

        List<String> publicClaims = new ArrayList<>();
        List<String> sdClaims = new ArrayList<>();

        try {
            IssuerConfig issuerConfig = issuersService.getIssuerConfig(issuerId, credentialType);
            if (issuerConfig != null) {
                VerifiableCredentialResponseDTO credentialResponse = VerifiableCredentialResponseDTO.fromIssuerConfig(issuerConfig, "en", decryptedCredentialDTO.getId());
                credentialTypeDisplayName = credentialResponse.getCredentialTypeDisplayName();
                credentialTypeLogo = credentialResponse.getCredentialTypeLogo();
            }
        } catch (InvalidIssuerIdException | ApiNotAccessibleException e) {
            log.warn("Failed to fetch issuer config for issuerId: {}, credentialType: {}", issuerId, credentialType, e);
        }

        if (CredentialFormat.isSdJwt(decryptedCredentialDTO.getCredential().getFormat())) {
            CredentialFormatHandler credentialFormatHandler = credentialFormatHandlerFactory.getHandler(decryptedCredentialDTO.getCredential().getFormat());
            Map<String, Map<String, Object>> allClaims = (Map<String, Map<String, Object>>) credentialFormatHandler.extractAllCredentialProperties(decryptedCredentialDTO.getCredential());

            publicClaimsMap = allClaims.get("publicClaims");
            sdClaimsMap = allClaims.get("sdClaims");

            if (publicClaimsMap != null) {
                publicClaims = extractPublicClaimPaths(publicClaimsMap);
            }

            if (sdClaimsMap != null) {
                sdClaims = extractSdClaimPaths(sdClaimsMap);
            }

        }


        return CredentialDTO.builder()
                .credentialId(decryptedCredentialDTO.getId())
                .credentialTypeDisplayName(credentialTypeDisplayName)
                .credentialTypeLogo(credentialTypeLogo)
                .format(decryptedCredentialDTO.getCredential().getFormat())
                .claims(publicClaims)
                .sdClaims(sdClaims)
                .build();
    }

    private List<String> extractPublicClaimPaths(Map<String, Object> publicClaimsMap) {
        List<String> paths = new ArrayList<>();
        Object credentialSubject = publicClaimsMap.get(CREDENTIAL_SUBJECT);
        if (credentialSubject instanceof Map) {
            Map<String, Object> csMap = (Map<String, Object>) credentialSubject;
            collectPaths(csMap, "$", paths);
        } else {
            List<String> metadataKeys = Arrays.asList("vct", "cnf", "iss", "sub", "aud", "exp", "nbf", "iat", "jti", SD, "_sd_alg", "id");
            Map<String, Object> filteredMap = new HashMap<>(publicClaimsMap);
            metadataKeys.forEach(filteredMap::remove);
            collectPaths(filteredMap, "$", paths);
        }
        return paths;
    }

    private List<String> extractSdClaimPaths(Map<String, Object> sdClaimsMap) {
        List<String> paths = new ArrayList<>();
        for (String key : sdClaimsMap.keySet()) {
            String cleanKey = key.startsWith(CREDENTIAL_SUBJECT_PREFIX)
                    ? key.substring(CREDENTIAL_SUBJECT_PREFIX.length())
                    : key;
            paths.add(JSON_PATH_PREFIX + cleanKey);
        }
        return paths;
    }

    private void collectPaths(Map<String, Object> publicClaimsMap, String prefix, List<String> paths) {
        for (Map.Entry<String, Object> entry : publicClaimsMap.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            // Skip _sd keys
            if (SD.equals(key)) {
                continue;
            }

            String currentPath = prefix + "." + key;

            if (value instanceof Map) {
                collectPaths((Map<String, Object>) value, currentPath, paths);
            } else if (value instanceof List<?> listValue) {
                if (hasUniformKeys(listValue)) {
                    paths.add(currentPath);
                } else {
                    paths.add(currentPath);
                    for (Object item : listValue) {
                        if (item instanceof Map<?, ?> mapItem) {
                            collectPaths((Map<String, Object>) mapItem, currentPath, paths);
                        }
                    }
                }
            } else {
                paths.add(currentPath);
            }
        }
    }

    private Set<String> extractFormatConstraintKeys(InputDescriptor descriptor) {
        Map<String, Map<String, List<String>>> format = descriptor.getFormat();
        if (format == null || format.isEmpty()) {
            return Collections.singleton(descriptor.getId());
        }

        Set<String> result = new HashSet<>();
        if (format.containsKey(CredentialFormat.VC_SD_JWT.getFormat()) || format.containsKey(CredentialFormat.DC_SD_JWT.getFormat())) {
            result.add(SD_JWT_ALG_VALUES_KEY);
        }
        if (format.containsKey(LDP_VC_FORMAT)) {
            result.add(PROOF_TYPE_KEY);
        }

        return result.isEmpty() ? Collections.singleton(descriptor.getId()) : result;
    }

    private boolean hasUniformKeys(List<?> list) {
        List<Set<Object>> keySets = list.stream()
                .filter(item -> item instanceof Map<?, ?>)
                .map(item -> {
                    Map<?, ?> m = (Map<?, ?>) item;
                    return new HashSet<Object>(m.keySet());
                })
                .collect(Collectors.toList());
    
        if (keySets.size() < 2 || keySets.size() != list.size()) {
            return false;
        }

        Set<Object> intersectionKeys = new HashSet<>(keySets.getFirst());
        keySets.forEach(intersectionKeys::retainAll);

        return !intersectionKeys.isEmpty();
    }
}