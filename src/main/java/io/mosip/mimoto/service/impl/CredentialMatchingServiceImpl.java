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
import io.mosip.mimoto.service.CredentialMatchingService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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
    private static final String TYPE_PATH = "$.type";
    private static final String LDP_VC_FORMAT = "ldp_vc";
    private static final String PROOF_TYPE_KEY = "proof_type";

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private IssuersService issuersService;

    @Autowired
    private OpenID4VPService openID4VPService;

    @Autowired
    private WalletCredentialService walletCredentialService;

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

        if (!CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(vcFormat) || !descriptorFormat.containsKey(LDP_VC_FORMAT)) {
            return false;
        }

        Map<String, List<String>> ldpVcFormat = descriptorFormat.get(LDP_VC_FORMAT);

        if (!ldpVcFormat.containsKey(PROOF_TYPE_KEY)) {
            return true;
        }

        VCCredentialProperties ldpCredential = objectMapper.convertValue(vc.getCredential(), VCCredentialProperties.class);
        String vcProofType = ldpCredential.getProof() != null ? ldpCredential.getProof().getType() : null;
        List<String> requiredProofTypes = ldpVcFormat.get(PROOF_TYPE_KEY);

        return vcProofType != null && requiredProofTypes.contains(vcProofType);
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

        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(format)) {
            Object credentialData = vc.getCredential();

            if (credentialData instanceof Map) {
                return credentialData;
            } else {
                return objectMapper.convertValue(credentialData, VCCredentialProperties.class);
            }
        } else if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(format) || CredentialFormat.DC_SD_JWT.getFormat().equalsIgnoreCase(format)) {
            throw new InvalidRequestException(UNSUPPORTED_FORMAT.getErrorCode(), 
                "SD-JWT credential format (" + format + ") is not supported for credential matching");
        }

        return vc.getCredential();
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

        return CredentialDTO.builder()
                .credentialId(decryptedCredentialDTO.getId())
                .credentialTypeDisplayName(credentialTypeDisplayName)
                .credentialTypeLogo(credentialTypeLogo)
                .format(decryptedCredentialDTO.getCredential()
                .getFormat())
                .build();
    }

}