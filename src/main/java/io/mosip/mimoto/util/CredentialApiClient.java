package io.mosip.mimoto.util;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.mosip.mimoto.constant.DPoPConstants;
import io.mosip.mimoto.exception.DPoPChallengeException;
import io.mosip.mimoto.exception.InvalidRequestException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Iterator;
import java.util.Objects;

import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;

/**
 * HTTP client for OpenID4VCI credential endpoints, including DPoP proofs and Bearer downgrade.
 */
@Slf4j
@Component
public class CredentialApiClient {

    private static final String CONTENT_TYPE = "Content-Type";

    private final RestTemplate plainRestTemplate;

    public CredentialApiClient(@Qualifier("plainRestTemplate") RestTemplate plainRestTemplate) {
        this.plainRestTemplate = plainRestTemplate;
    }

    /**
     * Posts a credential request supporting DPoP authorization and Bearer downgrade (RFC 9449 §7.2).
     * Retries once as Bearer when the issuer rejects the DPoP auth scheme. Never downgrades a
     * use_dpop_nonce challenge or an issuer that requires a DPoP-bound token to be presented with a
     * DPoP proof.
     */
    public <T> T postCredentialApi(String uri, MediaType mediaType, Object requestType, Class<T> responseClass,
                                   String accessToken, String tokenType, String dPoPProof) {
        boolean useDPoP = shouldSendDPoP(tokenType, dPoPProof);
        try {
            log.info("CredentialApiClient::postCredentialApi()::entry uri: {} dPoP: {}", uri, useDPoP);
            return exchangeCredential(uri, mediaType, requestType, responseClass, accessToken, useDPoP, dPoPProof);
        } catch (HttpStatusCodeException e) {
            if (!useDPoP || !isUnauthorizedOrForbidden(e.getStatusCode())) {
                return parseCredentialErrorBody(uri, responseClass, e);
            }

            HttpHeaders responseHeaders = e.getResponseHeaders();
            String wwwAuthenticate = responseHeaders != null
                    ? responseHeaders.getFirst(DPoPConstants.WWW_AUTHENTICATE_HEADER) : null;
            WwwAuthenticateChallenge challenge = WwwAuthenticateChallenge.parse(wwwAuthenticate);
            String nonce = DPoPResponseHelper.dPoPNonce(responseHeaders);
            String responseBody = e.getResponseBodyAsString();

            // Propagate the nonce challenge so the caller can retry credential download
            // with a new DPoP proof that includes the server-issued nonce (RFC 9449).
            if (isDPoPNonceChallenge(challenge, nonce, responseBody)) {
                throw new DPoPChallengeException(e.getStatusCode(), responseHeaders, responseBody);
            }

            if (shouldRetryWithBearer(challenge, responseBody)) {
                log.warn("CredentialApiClient::postCredentialApi()::DPoP rejected by issuer, retrying with Bearer for uri: {} wwwAuthenticate: {} body: {}",
                        uri, wwwAuthenticate, responseBody);
                try {
                    return exchangeCredential(uri, mediaType, requestType, responseClass, accessToken, false, null);
                } catch (HttpStatusCodeException retryException) {
                    return parseCredentialErrorBody(uri, responseClass, retryException);
                }
            }

            return parseCredentialErrorBody(uri, responseClass, e);
        } catch (DPoPChallengeException | InvalidRequestException e) {
            throw e;
        } catch (Exception e) {
            log.error("CredentialApiClient::postCredentialApi()::error uri: {} {}", uri, e.getMessage(), e);
            return null;
        }
    }

    private static void requireHttpsCredentialEndpoint(String uri) {
        URI parsed;
        try {
            parsed = URI.create(StringUtils.defaultString(uri).trim());
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                    "Credential endpoint must use HTTPS");
        }
        if (!"https".equalsIgnoreCase(parsed.getScheme())) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                    "Credential endpoint must use HTTPS");
        }
    }

    private static boolean isUnauthorizedOrForbidden(org.springframework.http.HttpStatusCode statusCode) {
        return statusCode == HttpStatus.UNAUTHORIZED || statusCode == HttpStatus.FORBIDDEN;
    }

    /**
     * use_dpop_nonce + DPoP-Nonce must be returned to the client for a new proof — never Bearer-downgraded.
     */
    private static boolean isDPoPNonceChallenge(WwwAuthenticateChallenge challenge, String nonce, String responseBody) {
        if (StringUtils.isBlank(nonce)) {
            return false;
        }
        if (challenge.isDPoP() && DPoPConstants.USE_DPOP_NONCE_ERROR.equals(challenge.getError())) {
            return true;
        }
        return StringUtils.isNotBlank(responseBody)
                && responseBody.contains(DPoPConstants.USE_DPOP_NONCE_ERROR);
    }

    /**
     * Retry once as Bearer when DPoP was rejected, unless the issuer is asking for a DPoP nonce
     * or a DPoP-bound token to be presented with a DPoP proof.
     */
    private static boolean shouldRetryWithBearer(WwwAuthenticateChallenge challenge, String responseBody) {
        return !indicatesUseDPoPNonce(challenge, responseBody) && !issuerRequiresDPoPProof(challenge, responseBody);
    }

    /**
     * Send DPoP whenever a proof was built, even if the Authorization Server returned
     * {@code token_type: Bearer} for a DPoP-bound token. Issuers that do not support DPoP
     * are handled by one Bearer retry.
     */
    private static boolean shouldSendDPoP(String tokenType, String dPoPProof) {
        return StringUtils.isNotBlank(dPoPProof);
    }

    /**
     * RFC 9449 resource servers reject a Bearer retry when the access token is DPoP-bound.
     */
    private static boolean issuerRequiresDPoPProof(WwwAuthenticateChallenge challenge, String responseBody) {
        if (DPoPConstants.INVALID_DPOP_PROOF_ERROR.equals(challenge.getError())
                || (challenge.isDPoP() && DPoPConstants.INVALID_TOKEN_ERROR.equals(challenge.getError()))) {
            return true;
        }
        if (StringUtils.isBlank(responseBody)) {
            return false;
        }
        return responseBody.contains(DPoPConstants.INVALID_DPOP_PROOF_ERROR)
                || responseBody.contains(DPoPConstants.DPOP_BOUND_TOKEN_MESSAGE);
    }

    private static boolean indicatesUseDPoPNonce(WwwAuthenticateChallenge challenge, String responseBody) {
        if (challenge.isDPoP() && DPoPConstants.USE_DPOP_NONCE_ERROR.equals(challenge.getError())) {
            return true;
        }
        return StringUtils.isNotBlank(responseBody)
                && responseBody.contains(DPoPConstants.USE_DPOP_NONCE_ERROR);
    }

    private <T> T exchangeCredential(String uri, MediaType mediaType, Object requestType, Class<T> responseClass,
                                     String accessToken, boolean useDPoP, String dPoPProof) {
        requireHttpsCredentialEndpoint(uri);
        HttpEntity<Object> requestEntity = setCredentialRequestHeader(requestType, mediaType, accessToken, useDPoP, dPoPProof);
        ResponseEntity<T> response = plainRestTemplate.exchange(uri, HttpMethod.POST, requestEntity, responseClass);
        return response.getBody();
    }

    private <T> T parseCredentialErrorBody(String uri, Class<T> responseClass, HttpStatusCodeException e) {
        log.error("CredentialApiClient::postCredentialApi()::client error uri: {} status: {} wwwAuthenticate: {} dPoPNonce: {} body: {}",
                uri,
                e.getStatusCode(),
                e.getResponseHeaders() != null ? e.getResponseHeaders().getFirst(DPoPConstants.WWW_AUTHENTICATE_HEADER) : null,
                e.getResponseHeaders() != null ? e.getResponseHeaders().getFirst(DPoPConstants.DPOP_NONCE_HEADER) : null,
                e.getResponseBodyAsString());
        try {
            ObjectMapper mapper = new ObjectMapper()
                    .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
            String body = e.getResponseBodyAsString();
            if (XmlErrorToJson.isXml(body)) {
                ObjectNode errorJson = XmlErrorToJson.toJson(body);
                return errorJson == null ? null : mapper.convertValue(errorJson, responseClass);
            }
            return mapper.readValue(body, responseClass);
        } catch (Exception ex) {
            log.error("CredentialApiClient::postCredentialApi()::failed to parse error body as {}: {}",
                    responseClass.getSimpleName(), ex.getMessage());
            return null;
        }
    }

    private HttpEntity<Object> setCredentialRequestHeader(Object requestType, MediaType mediaType, String accessToken,
                                                          boolean useDPoP, String dPoPProof) {
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        if (mediaType != null) {
            headers.add(CONTENT_TYPE, mediaType.toString());
        }

        if (useDPoP) {
            headers.add(HttpHeaders.AUTHORIZATION, DPoPConstants.DPOP_TOKEN_TYPE + " " + accessToken);
            headers.add(DPoPConstants.DPOP_HEADER, dPoPProof);
        } else {
            headers.add(HttpHeaders.AUTHORIZATION, DPoPConstants.BEARER_TOKEN_TYPE + " " + accessToken);
        }

        if (requestType != null) {
            try {
                HttpEntity<Object> httpEntity = (HttpEntity<Object>) requestType;
                HttpHeaders httpHeader = httpEntity.getHeaders();
                Iterator<String> iterator = httpHeader.keySet().iterator();
                while (iterator.hasNext()) {
                    String key = iterator.next();
                    if (!(headers.containsKey(CONTENT_TYPE) && key.equals(CONTENT_TYPE))) {
                        headers.add(key, Objects.requireNonNull(httpHeader.get(key)).get(0));
                    }
                }
                return new HttpEntity<>(httpEntity.getBody(), headers);
            } catch (ClassCastException | NullPointerException ex) {
                return new HttpEntity<>(requestType, headers);
            }
        }
        return new HttpEntity<>(headers);
    }
}
