package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidVerifierException;
import io.mosip.mimoto.repository.VerifierRepository;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.mimoto.constant.OpenID4VPConstants;
import io.mosip.mimoto.util.UrlParameterUtils;
import io.mosip.mimoto.util.Utilities;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.validator.routines.UrlValidator;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.cache.annotation.Cacheable;

import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.apache.commons.validator.routines.UrlValidator.ALLOW_ALL_SCHEMES;
import static org.apache.commons.validator.routines.UrlValidator.ALLOW_LOCAL_URLS;

@Slf4j
@Service
public class VerifierServiceImpl implements VerifierService {

    private final Utilities utilities;

    private final ObjectMapper objectMapper;

    private final VerifierRepository verifierRepository;

    private static final PathMatcher pathMatcher;
    private static final UrlValidator urlValidator;

    static {
        pathMatcher = new AntPathMatcher();
        urlValidator = new UrlValidator(ALLOW_ALL_SCHEMES+ALLOW_LOCAL_URLS);
    }

    public VerifierServiceImpl(Utilities utilities, ObjectMapper objectMapper, VerifierRepository verifierRepository) {
        this.utilities = utilities;
        this.objectMapper = objectMapper;
        this.verifierRepository = verifierRepository;
    }

    @Cacheable(value = "preRegisteredTrustedVerifiersCache", key = "'preRegisteredTrustedVerifiers'")
    public VerifiersDTO getTrustedVerifiers() throws ApiNotAccessibleException, JsonProcessingException {
        String trustedVerifiersJsonValue = utilities.getTrustedVerifiersJsonValue();
        if (trustedVerifiersJsonValue == null) {
            throw new ApiNotAccessibleException();
        }
        return objectMapper.readValue(trustedVerifiersJsonValue, VerifiersDTO.class);
    }

    public Optional<VerifierDTO> getVerifierByClientId(String clientId) throws ApiNotAccessibleException, JsonProcessingException {
        VerifiersDTO verifiersDTO = getTrustedVerifiers();
        return verifiersDTO.getVerifiers().stream().filter(verifier -> verifier.getClientId().equals(clientId)).findFirst();
    }

    @Override
    public VerifierDTO validateVerifier(String clientId, String responseUri, String redirectUri) throws ApiNotAccessibleException, JsonProcessingException {
        log.info("Started the presentation Validation");
        VerifierDTO verifierDTO = getVerifierByClientId(clientId)
                .orElseThrow(() -> new InvalidVerifierException(
                        ErrorConstants.INVALID_CLIENT.getErrorCode(),
                        ErrorConstants.INVALID_CLIENT.getErrorMessage()));

        if (responseUri != null && !responseUri.trim().isEmpty()) {
            List<String> registeredResponseUris = Optional.ofNullable(verifierDTO.getResponseUris())
                    .orElseGet(Collections::emptyList);
            boolean isValidVerifier = registeredResponseUris.stream().anyMatch(registeredResponseUri ->
                    urlValidator.isValid(registeredResponseUri) &&
                            urlValidator.isValid(responseUri) &&
                            pathMatcher.match(registeredResponseUri, responseUri));
            if (!isValidVerifier) {
                throw new InvalidVerifierException(
                        ErrorConstants.INVALID_RESPONSE_URI.getErrorCode(),
                        ErrorConstants.INVALID_RESPONSE_URI.getErrorMessage());
            }
        } else {
            List<String> registeredRedirectUris = Optional.ofNullable(verifierDTO.getRedirectUris())
                    .orElseGet(Collections::emptyList);
            boolean isValidVerifier = registeredRedirectUris.stream().anyMatch(registeredRedirectUri ->
                    urlValidator.isValid(registeredRedirectUri) &&
                            urlValidator.isValid(redirectUri) &&
                            pathMatcher.match(registeredRedirectUri, redirectUri));
            if (!isValidVerifier) {
                throw new InvalidVerifierException(
                        ErrorConstants.INVALID_REDIRECT_URI.getErrorCode(),
                        ErrorConstants.INVALID_REDIRECT_URI.getErrorMessage());
            }
        }
        return verifierDTO;
    }

    @Override
    public boolean isVerifierTrustedByWallet(String verifierId, String walletId) {
        return verifierRepository.existsByWalletIdAndVerifierId(walletId, verifierId);
    }

    @Override
    public boolean isVerifierClientPreregistered(List<Verifier> preRegisteredVerifiers, String urlEncodedVPAuthorizationRequest) throws URISyntaxException {
        if (urlEncodedVPAuthorizationRequest == null || urlEncodedVPAuthorizationRequest.trim().isEmpty()) {
            log.warn("URL encoded VP authorization request is null or empty");
            return false;
        }

        String clientId = UrlParameterUtils.extractQueryParameter(urlEncodedVPAuthorizationRequest, OpenID4VPConstants.CLIENT_ID_PARAM);
        String responseUriValue = UrlParameterUtils.extractQueryParameter(urlEncodedVPAuthorizationRequest, OpenID4VPConstants.RESPONSE_URI_PARAM);
        List<String> responseUris = responseUriValue != null ? List.of(responseUriValue) : List.of();

        if (clientId == null || clientId.trim().isEmpty()) {
            log.warn("No client_id found in the authorization request URL");
            return false;
        }
        if (responseUris.isEmpty()) {
            log.warn("No response_uri found in the authorization request URL");
            return false;
        }
        return preRegisteredVerifiers.stream().anyMatch(verifier -> clientId.equals(verifier.getClientId()) && verifier.getResponseUris().containsAll(responseUris));
    }

}
