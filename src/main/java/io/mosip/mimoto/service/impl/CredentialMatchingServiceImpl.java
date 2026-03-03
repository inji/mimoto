package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.mimoto.dto.MatchingCredentialsResponseDTO;
import io.mosip.mimoto.dto.MatchingCredentialsDTO;
import io.mosip.mimoto.dto.CredentialDTO;
import io.mosip.mimoto.dto.mimoto.IssuerConfig;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.InvalidRequestException;
import static io.mosip.mimoto.exception.ErrorConstants.UNSUPPORTED_FORMAT;
import io.mosip.mimoto.service.CredentialFormatHandlerFactory;
import io.mosip.mimoto.service.CredentialFormatHandler;
import io.mosip.mimoto.service.CredentialMatchingService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.JwtUtils;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

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

    private final ObjectMapper objectMapper;

    private final IssuersService issuersService;

    private final OpenID4VPService openID4VPService;

    private final WalletCredentialService walletCredentialService;

    public CredentialMatchingServiceImpl(ObjectMapper objectMapper, IssuersService issuersService, OpenID4VPService openID4VPService, WalletCredentialService walletCredentialService) {
        this.objectMapper = objectMapper;
        this.issuersService = issuersService;
        this.openID4VPService = openID4VPService;
        this.walletCredentialService = walletCredentialService;
    }

    @Autowired
    private CredentialFormatHandlerFactory credentialFormatHandlerFactory;

    @Override
    public MatchingCredentialsDTO getMatchingCredentials(VerifiablePresentationSessionData sessionData, String walletId, String base64Key) throws ApiNotAccessibleException, IOException {
        log.info("Getting matching credentials with wallet data for walletId: {}", walletId);

        // Extract presentation definition from the session data
        PresentationDefinition presentationDefinition = openID4VPService.resolvePresentationDefinition(sessionData.getPresentationId(), sessionData.getAuthorizationRequest(), sessionData.isVerifierClientPreregistered());

        if (presentationDefinition == null) {
            log.warn("No presentation definition found in session data");
            throw new IllegalArgumentException("Presentation definition not found in session data");
        }

        validateInputParameters(presentationDefinition, walletId, base64Key);

        List<DecryptedCredentialDTO> decryptedCredentials = walletCredentialService.getDecryptedCredentials(walletId, base64Key);
        if (decryptedCredentials.isEmpty()) {
            MatchingCredentialsResponseDTO emptyResponse = createEmptyResponseWithMissingClaims(presentationDefinition);
            return MatchingCredentialsDTO.builder()
                    .matchingCredentialsResponse(emptyResponse)
                    .matchingCredentials(new ArrayList<>())
                    .build();
        }

        List<InputDescriptor> descriptors = presentationDefinition.getInputDescriptors();
        Map<Integer, List<CredentialDTO>> matchingCredentialsByDescriptor = new HashMap<>();
        Set<String> missingClaims = new HashSet<>();

        IntStream.range(0, descriptors.size())
                .forEach(i -> {
                    InputDescriptor descriptor = descriptors.get(i);
                    List<CredentialDTO> matches = decryptedCredentials.stream()
                            .filter(decrypted -> matchesInputDescriptor(decrypted.getCredential(), descriptor))
                            .map(this::buildAvailableCredential)
                            .collect(Collectors.toList());

                    if (!matches.isEmpty()) {
                        matchingCredentialsByDescriptor.put(i, matches);
                    } else {
                        missingClaims.addAll(extractClaimsFromInputDescriptor(descriptor));
                    }
                });

        // Flatten all matching credentials into a single list, removing duplicates by credential ID
        Set<String> addedCredentialIds = new HashSet<>();
        List<CredentialDTO> availableCredentials = matchingCredentialsByDescriptor.values().stream()
                .flatMap(List::stream)
                .filter(credential -> addedCredentialIds.add(credential.getCredentialId()))
                .collect(Collectors.toList());

        MatchingCredentialsResponseDTO matchingCredentialsResponse = MatchingCredentialsResponseDTO.builder().availableCredentials(availableCredentials).missingClaims(missingClaims).build();

        // Filter decrypted credentials to only include matched ones
        Set<String> matchedCredentialIds = availableCredentials.stream()
                .map(CredentialDTO::getCredentialId)
                .collect(Collectors.toSet());

        List<DecryptedCredentialDTO> matchingCredentials = decryptedCredentials.stream().filter(credential -> matchedCredentialIds.contains(credential.getId())).collect(Collectors.toList());

        return MatchingCredentialsDTO.builder()
                .matchingCredentialsResponse(matchingCredentialsResponse)
                .matchingCredentials(matchingCredentials)
                .build();
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
        return MatchingCredentialsResponseDTO.builder()
                .availableCredentials(Collections.emptyList())
                .missingClaims(new HashSet<>(extractRequiredClaims(presentationDefinition)))
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

        if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(vcFormat) && descriptorFormat.containsKey(CredentialFormat.VC_SD_JWT.getFormat())) {
            return matchesSdJwtAlgorithm(vc, descriptorFormat);
        }
        if(CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(vcFormat) && descriptorFormat.containsKey(LDP_VC_FORMAT)) {
            Map<String, List<String>> ldpVcFormat = descriptorFormat.get(LDP_VC_FORMAT);

            if(ldpVcFormat == null) {
                return true;
            }

            if (!ldpVcFormat.containsKey(PROOF_TYPE_KEY)) {
                return true;
            }

            VCCredentialProperties ldpCredential = objectMapper.convertValue(vc.getCredential(), VCCredentialProperties.class);
            String vcProofType = ldpCredential.getProof() != null ? ldpCredential.getProof().getType() : null;
            List<String> requiredProofTypes = ldpVcFormat.get(PROOF_TYPE_KEY);

            if(requiredProofTypes == null || requiredProofTypes.isEmpty()) {
                return true;
            }

            return vcProofType != null && requiredProofTypes.contains(vcProofType);
        }
        return false;
    }

    private boolean matchesSdJwtAlgorithm(VCCredentialResponse vc, Map<String, Map<String, List<String>>> requestFormat) {
        if(vc.getCredential() == null || !(vc.getCredential() instanceof String sdJwtString)) {
            return false;
        }
        String algorithm = extractSdJwtAlgorithm(sdJwtString);
        if (algorithm == null){
            return false;
        }

        Map<String, List<String>> formatConfig = requestFormat.get(CredentialFormat.VC_SD_JWT.getFormat());
        if (formatConfig != null) {
            List<?> algorithmValues = formatConfig.get(SD_JWT_ALG_VALUES_KEY);
            if (algorithmValues != null) {
                return algorithmValues.contains(algorithm);
            }
            return true; // If no specific algorithms are required, any algorithm is acceptable
        }
        return false;
    }

    private String extractSdJwtAlgorithm(String sdJwtString) {
        if(sdJwtString == null || sdJwtString.trim().isEmpty()) {
            return null;
        }
        try {
            Map<String, Object> header = JwtUtils.parseJwtHeader(sdJwtString);
            return (String) header.get("alg");
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

        if (matches == null || matches.isEmpty()) {
            return false;
        }

        return matches.stream().anyMatch(match -> matchesFilter(match, filter));
    }

    private Object getCredentialData(VCCredentialResponse vc) {
        String format = vc.getFormat();
        CredentialFormatHandler credentialFormatHandler = credentialFormatHandlerFactory.getHandler(vc.getFormat());

        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(format)) {
            return credentialFormatHandler.extractAllCredentialProperties(vc);
        }
        else if(CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(format)){
            Object extracted = credentialFormatHandler.extractAllCredentialProperties(vc);
            if (extracted == null) {
                return Collections.emptyMap();
            }
            Map<String, Map<String, Object>> allCredentialProperties = (Map<String, Map<String, Object>>) extracted;
            Map<String, Object> flattenedPropertiesMap = new HashMap<>();
            allCredentialProperties.values().forEach(flattenedPropertiesMap::putAll);
            return flattenedPropertiesMap;
        }
        else{
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

        if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(decryptedCredentialDTO.getCredential().getFormat())) {
            CredentialFormatHandler credentialFormatHandler = credentialFormatHandlerFactory.getHandler(CredentialFormat.VC_SD_JWT.getFormat());
            Map<String, Map<String, Object>> allClaims = (Map<String, Map<String, Object>>) credentialFormatHandler.extractAllCredentialProperties(decryptedCredentialDTO.getCredential());

            publicClaimsMap = allClaims.get("publicClaims");
            sdClaimsMap = allClaims.get("sdClaims");

            if (publicClaimsMap != null) {
                publicClaims = new ArrayList<>(publicClaimsMap.keySet());

                List<String> metadataKeys = Arrays.asList("vct", "cnf", "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "_sd", "_sd_alg", "id");
                metadataKeys.forEach(publicClaims::remove);
            }

            if (sdClaimsMap != null) {
                sdClaims = extractJsonPaths(sdClaimsMap);
            }

        }


        return CredentialDTO.builder()
                .credentialId(decryptedCredentialDTO.getId())
                .credentialTypeDisplayName(credentialTypeDisplayName)
                .credentialTypeLogo(credentialTypeLogo)
                .format(decryptedCredentialDTO.getCredential().getFormat())
                .publicClaims(publicClaims)
                .sdClaims(sdClaims)
                .build();
    }

    private List<String> extractJsonPaths(Map<String, Object> sdClaimsMap) {
        List<String> paths = new ArrayList<>();
        for (Map.Entry<String, Object> entry : sdClaimsMap.entrySet()) {
            collectPaths(entry.getKey(), entry.getValue(), paths);
        }
        return paths;
    }

    private void collectPaths(String currentPath, Object value, List<String> paths) {
        if (value instanceof Map<?, ?> mapValue) {
            for (Map.Entry<?, ?> entry : mapValue.entrySet()) {
                collectPaths(currentPath + "." + entry.getKey(), entry.getValue(), paths);
            }
        } else if (value instanceof List<?> listValue) {
            for (int i = 0; i < listValue.size(); i++) {
                collectPaths(currentPath + "[" + i + "]", listValue.get(i), paths);
            }
        } else {
            paths.add(currentPath);
        }
    }

}