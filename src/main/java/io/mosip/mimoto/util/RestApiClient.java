package io.mosip.mimoto.util;

import com.google.gson.Gson;
import io.mosip.mimoto.constant.DpopConstants;
import io.mosip.mimoto.core.http.RequestWrapper;
import io.mosip.mimoto.dto.SecretKeyRequest;
import io.mosip.mimoto.exception.DpopChallengeException;
import io.mosip.mimoto.exception.TokenGenerationFailedException;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.LoggerFactory;
import org.apache.commons.lang.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.util.Iterator;
import java.util.Objects;

/**
 * The Class RestApiClient.
 *
 * @author Rishabh Keshari
 */
@Slf4j
@Component
public class RestApiClient {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(RestApiClient.class);

    public static final String TOKEN = "token";
    public static final String CONTENT_TYPE = "Content-Type";

    private static final String AUTHORIZATION = "Authorization=";
    /**
     * The builder.
     */
    @Autowired
    @Qualifier("selfTokenRestTemplate")
    private RestTemplate restTemplate;

    @Autowired
    @Qualifier("plainRestTemplate")
    private RestTemplate plainRestTemplate;

    @Value("${wallet.binding.partner.id}")
    private String partnerId;

    @Value("${wallet.binding.partner.api.key}")
    private String partnerApiKey;

    @Value("${mosip.authmanager.client-token-endpoint}")
    private String authBaseUrl;

    @Value("${mosip.iam.adapter.clientid}")
    private String clientId;

    @Value("${mosip.iam.adapter.clientsecret}")
    private String secret;

    @Value("${mosip.iam.adapter.appid}")
    private String appId;

    @Value("${mosip.iam.adapter.disable-self-token-rest-template:false}")
    private boolean disableSelfTokenRestTemplate;

    @Autowired
    Environment environment;
    /**
     * HTTP GET API
     *
     * @param <T>
     * @param uri
     * @param responseType
     * @return
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public <T> T getApi(URI uri, Class<?> responseType) throws Exception {
        T result = null;
        RestTemplate rt = restTemplate;
        if (disableSelfTokenRestTemplate) {
            rt = plainRestTemplate;
        }
        try {
            log.info("RestApiClient::getApi()::entry uri: {}", uri);
            result = (T) rt.exchange(uri, HttpMethod.GET, setRequestHeader(null, null), responseType)
                    .getBody();
        } catch (Exception e) {
            log.error("RestApiClient::getApi()::error uri: {} {} {}", uri, e.getMessage(), e);
        }
        return result;
    }

    /**
     * HTTP GET API
     *
     * @param <T>
     * @param url
     * @param responseType
     * @return
     */
    @SuppressWarnings("unchecked")
    public <T> T getApi(String url, Class<?> responseType) {
        T result = null;
        RestTemplate rt = restTemplate;
        if (disableSelfTokenRestTemplate) {
            rt = plainRestTemplate;
        }
        try {
            log.info("RestApiClient::getApi()::entry uri: {}", url);
            result = (T) rt.getForObject(url, responseType);
        } catch (Exception e) {
            log.error("RestApiClient::getApi()::error uri:{} {} {}", url, e.getMessage(), e);
        }
        return result;
    }

    /**
     * HTTP POST API
     *
     * @param <T>
     * @param uri
     * @param mediaType
     * @param requestType
     * @param responseClass
     * @return
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public <T> T postApi(String uri, MediaType mediaType, Object requestType, Class<?> responseClass) throws Exception {
        T result = null;
        RestTemplate rt = restTemplate;
        if (disableSelfTokenRestTemplate) {
            rt = plainRestTemplate;
        }
        try {
            log.info("RestApiClient::postApi()::entry uri: {}", uri);
            result = (T) rt.postForObject(uri, setRequestHeader(requestType, mediaType), responseClass);
        } catch (Exception e) {
            log.error("RestApiClient::postApi()::error uri: {} {} {}", uri, e.getMessage(), e);
        }
        return result;
    }

    public <T> T postApi(String uri, MediaType mediaType, Object requestType, Class<?> responseClass, boolean useBearerToken) throws Exception {
        T result = null;
        try {
            log.info("RestApiClient::postApi()::entry uri: {}", uri);
            result = (T) plainRestTemplate.postForObject(uri, setRequestHeader(requestType, mediaType, useBearerToken), responseClass);
        } catch (Exception e) {
            log.error("RestApiClient::postApi()::error uri: {} {} {}", uri, e.getMessage(), e);
            if (e instanceof HttpClientErrorException) {
                HttpClientErrorException ex = (HttpClientErrorException)e;
                if (ex.getStatusCode().value() == 401) {
                    // bearer token renew logic. Set token as empty so that it will auto-renew
                    System.setProperty(TOKEN, "");
                    // try one more time to pass existing call
                    result = (T) plainRestTemplate.postForObject(
                            uri, setRequestHeader(requestType, mediaType, useBearerToken), responseClass);
                }
            }
        }
        return result;
    }

    public <T> T postApi(String uri, MediaType mediaType, Object requestType, Class<?> responseClass, String bearerToken){
        T result = null;
        try {
            log.info("RestApiClient::postApi()::entry uri: {}", uri);
            result = (T) plainRestTemplate.postForObject(uri, setRequestHeader(requestType, mediaType, bearerToken), responseClass);
        } catch (Exception e) {
            log.error("RestApiClient::postApi()::error uri: {} {} {}", uri, e.getMessage(), e);
        }
        return result;
    }

    public <T> T postApiWithErrorResponse(String uri, MediaType mediaType, Object requestType, Class<T> responseClass, String bearerToken) {
        return postCredentialApi(uri, mediaType, requestType, responseClass, bearerToken, DpopConstants.BEARER_TOKEN_TYPE, null);
    }

    /**
     * Posts a credential request supporting DPoP authorization and Bearer downgrade (RFC 9449 §7.2).
     * Retries once as Bearer when the issuer rejects the DPoP auth scheme (including Certify-style
     * responses without a Bearer WWW-Authenticate header). Never downgrades a use_dpop_nonce
     * challenge or an issuer that requires a DPoP-bound token to be presented with a DPoP proof.
     */
    public <T> T postCredentialApi(String uri, MediaType mediaType, Object requestType, Class<T> responseClass,
                                   String accessToken, String tokenType, String dpopProof) {
        boolean useDpop = shouldSendDpop(tokenType, dpopProof);
        try {
            log.info("RestApiClient::postCredentialApi()::entry uri: {} dpop: {}", uri, useDpop);
            return exchangeCredential(uri, mediaType, requestType, responseClass, accessToken, useDpop, dpopProof);
        } catch (org.springframework.web.client.HttpStatusCodeException e) {
            if (!useDpop || !isUnauthorizedOrForbidden(e.getStatusCode())) {
                return parseCredentialErrorBody(uri, responseClass, e);
            }

            HttpHeaders responseHeaders = e.getResponseHeaders();
            String wwwAuthenticate = responseHeaders != null
                    ? responseHeaders.getFirst(DpopConstants.WWW_AUTHENTICATE_HEADER) : null;
            WwwAuthenticateChallenge challenge = WwwAuthenticateChallenge.parse(wwwAuthenticate);
            String nonce = responseHeaders != null
                    ? responseHeaders.getFirst(DpopConstants.DPOP_NONCE_HEADER) : null;
            String responseBody = e.getResponseBodyAsString();

            if (isDpopNonceChallenge(challenge, nonce, responseBody)) {
                throw new DpopChallengeException(e.getStatusCode(), responseHeaders, responseBody);
            }

            if (shouldRetryWithBearer(challenge, responseBody)) {
                log.warn("RestApiClient::postCredentialApi()::DPoP rejected by issuer, retrying with Bearer for uri: {} wwwAuthenticate: {} body: {}",
                        uri, wwwAuthenticate, responseBody);
                try {
                    return exchangeCredential(uri, mediaType, requestType, responseClass, accessToken, false, null);
                } catch (org.springframework.web.client.HttpStatusCodeException retryException) {
                    return parseCredentialErrorBody(uri, responseClass, retryException);
                }
            }

            return parseCredentialErrorBody(uri, responseClass, e);
        } catch (DpopChallengeException e) {
            throw e;
        } catch (Exception e) {
            log.error("RestApiClient::postCredentialApi()::error uri: {} {}", uri, e.getMessage(), e);
            return null;
        }
    }

    private static boolean isUnauthorizedOrForbidden(org.springframework.http.HttpStatusCode statusCode) {
        return statusCode == HttpStatus.UNAUTHORIZED || statusCode == HttpStatus.FORBIDDEN;
    }

    /**
     * use_dpop_nonce + DPoP-Nonce must be returned to the client for a new proof — never Bearer-downgraded.
     */
    private static boolean isDpopNonceChallenge(WwwAuthenticateChallenge challenge, String nonce, String responseBody) {
        if (StringUtils.isBlank(nonce)) {
            return false;
        }
        if (challenge.isDpop() && DpopConstants.USE_DPOP_NONCE_ERROR.equals(challenge.getError())) {
            return true;
        }
        return StringUtils.isNotBlank(responseBody)
                && responseBody.contains(DpopConstants.USE_DPOP_NONCE_ERROR);
    }

    /**
     * Retry as Bearer only when the issuer clearly does not support DPoP:
     * - WWW-Authenticate is Bearer-only (RFC 9449 §7.2), or
     * - response body matches Certify's DPoP-not-supported message.
     * Never Bearer-downgrades a use_dpop_nonce challenge, invalid_dpop_proof, or a DPoP-bound token rejection.
     */
    private static boolean shouldRetryWithBearer(WwwAuthenticateChallenge challenge, String responseBody) {
        if (indicatesUseDpopNonce(challenge, responseBody) || issuerRequiresDpopProof(challenge, responseBody)) {
            return false;
        }
        if (!challenge.isDpop() && challenge.isBearer()) {
            return true;
        }
        return isCertifyDpopUnsupported(responseBody);
    }

    /**
     * Certify / Spring Security returns XML 403 Forbidden when the Authorization scheme is DPoP.
     */
    private static boolean isCertifyDpopUnsupported(String responseBody) {
        if (StringUtils.isBlank(responseBody)) {
            return false;
        }
        if (responseBody.contains(DpopConstants.CERTIFY_DPOP_NOT_SUPPORTED_MESSAGE)) {
            return true;
        }
        String compact = responseBody.replaceAll("\\s+", "");
        return compact.contains("<error>Forbidden</error>") && compact.contains("<status>403</status>");
    }

    /**
     * Send DPoP only when a proof is present and the token is not a Bearer token.
     * Certify rejects Authorization: DPoP with a gateway 403.
     */
    private static boolean shouldSendDpop(String tokenType, String dpopProof) {
        if (StringUtils.isBlank(dpopProof)) {
            return false;
        }
        return !DpopConstants.BEARER_TOKEN_TYPE.equalsIgnoreCase(StringUtils.defaultString(tokenType));
    }

    /**
     * RFC 9449 resource servers reject a Bearer retry when the access token is DPoP-bound.
     */
    private static boolean issuerRequiresDpopProof(WwwAuthenticateChallenge challenge, String responseBody) {
        if (challenge.isDpop() && (DpopConstants.INVALID_DPOP_PROOF_ERROR.equals(challenge.getError())
                || DpopConstants.INVALID_TOKEN_ERROR.equals(challenge.getError()))) {
            return true;
        }
        if (StringUtils.isBlank(responseBody)) {
            return false;
        }
        return responseBody.contains(DpopConstants.INVALID_DPOP_PROOF_ERROR)
                || responseBody.contains(DpopConstants.DPOP_BOUND_TOKEN_MESSAGE);
    }

    private static boolean indicatesUseDpopNonce(WwwAuthenticateChallenge challenge, String responseBody) {
        if (challenge.isDpop() && DpopConstants.USE_DPOP_NONCE_ERROR.equals(challenge.getError())) {
            return true;
        }
        return StringUtils.isNotBlank(responseBody)
                && responseBody.contains(DpopConstants.USE_DPOP_NONCE_ERROR);
    }

    private <T> T exchangeCredential(String uri, MediaType mediaType, Object requestType, Class<T> responseClass,
                                     String accessToken, boolean useDpop, String dpopProof) {
        HttpEntity<Object> requestEntity = setCredentialRequestHeader(requestType, mediaType, accessToken, useDpop, dpopProof);
        ResponseEntity<T> response = plainRestTemplate.exchange(uri, HttpMethod.POST, requestEntity, responseClass);
        return response.getBody();
    }

    private <T> T parseCredentialErrorBody(String uri, Class<T> responseClass,
                                           org.springframework.web.client.HttpStatusCodeException e) {
        log.error("RestApiClient::postCredentialApi()::client error uri: {} status: {} wwwAuthenticate: {} dpopNonce: {} body: {}",
                uri,
                e.getStatusCode(),
                e.getResponseHeaders() != null ? e.getResponseHeaders().getFirst(DpopConstants.WWW_AUTHENTICATE_HEADER) : null,
                e.getResponseHeaders() != null ? e.getResponseHeaders().getFirst(DpopConstants.DPOP_NONCE_HEADER) : null,
                e.getResponseBodyAsString());
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper()
                    .disable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
            return mapper.readValue(e.getResponseBodyAsString(), responseClass);
        } catch (Exception ex) {
            log.error("RestApiClient::postCredentialApi()::failed to parse error body as {}: {}",
                    responseClass.getSimpleName(), ex.getMessage());
            return null;
        }
    }

    private HttpEntity<Object> setCredentialRequestHeader(Object requestType, MediaType mediaType, String accessToken,
                                                          boolean useDpop, String dpopProof) {
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        if (mediaType != null) {
            headers.add(CONTENT_TYPE, mediaType.toString());
        }

        if (useDpop) {
            headers.add(HttpHeaders.AUTHORIZATION, DpopConstants.DPOP_TOKEN_TYPE + " " + accessToken);
            headers.add(DpopConstants.DPOP_HEADER, dpopProof);
        } else {
            headers.add(HttpHeaders.AUTHORIZATION, DpopConstants.BEARER_TOKEN_TYPE + " " + accessToken);
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

    private HttpEntity<Object> setRequestHeader(Object requestType, MediaType mediaType, String bearerToken){
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        if (mediaType != null) {
            headers.add(CONTENT_TYPE, mediaType.toString());
        }
        headers.add("Authorization", "Bearer "+bearerToken);
        if (requestType != null) {
            try {
                HttpEntity<Object> httpEntity = (HttpEntity<Object>) requestType;
                HttpHeaders httpHeader = httpEntity.getHeaders();
                Iterator<String> iterator = httpHeader.keySet().iterator();
                while (iterator.hasNext()) {
                    String key = iterator.next();
                    if (!(headers.containsKey(CONTENT_TYPE) && key.equals(CONTENT_TYPE)))
                        headers.add(key, Objects.requireNonNull(httpHeader.get(key)).get(0));
                }

                return new HttpEntity<Object>(httpEntity.getBody(), headers);
            } catch (ClassCastException | NullPointerException e) {
                return new HttpEntity<Object>(requestType, headers);
            }
        } else
            return new HttpEntity<Object>(headers);
    }

    private HttpEntity<Object> setRequestHeader(Object requestType, MediaType mediaType) throws IOException {
        return setRequestHeader(requestType, mediaType, false);
    }

    /**
     * this method sets token to header of the request
     *
     * @param requestType
     * @param mediaType
     * @return
     * @throws IOException
     */
    @SuppressWarnings("unchecked")
    private HttpEntity<Object> setRequestHeader(Object requestType, MediaType mediaType, boolean useBearerToken) throws IOException {
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        if (mediaType != null) {
            headers.add(CONTENT_TYPE, mediaType.toString());
        }

        if (useBearerToken) {
            String bearerToken = System.getProperty(TOKEN);
            if (StringUtils.isEmpty(bearerToken))
                bearerToken = getBearerToken();
            headers.add("Authorization", bearerToken);
            headers.add("partner-id", partnerId);
            headers.add("partner-api-key", partnerApiKey);
        }

        if (requestType != null) {
            try {
                HttpEntity<Object> httpEntity = (HttpEntity<Object>) requestType;
                HttpHeaders httpHeader = httpEntity.getHeaders();
                Iterator<String> iterator = httpHeader.keySet().iterator();
                while (iterator.hasNext()) {
                    String key = iterator.next();
                    if (!(headers.containsKey(CONTENT_TYPE) && key.equals(CONTENT_TYPE)))
                        headers.add(key, Objects.requireNonNull(httpHeader.get(key)).get(0));
                }
                return new HttpEntity<Object>(httpEntity.getBody(), headers);
            } catch (ClassCastException | NullPointerException e) {
                return new HttpEntity<Object>(requestType, headers);
            }
        } else
            return new HttpEntity<Object>(headers);
    }

    private String getBearerToken() throws IOException {

        SecretKeyRequest request = new SecretKeyRequest(clientId, secret, appId);
        RequestWrapper<SecretKeyRequest> req = new RequestWrapper<>();
        req.setRequest(request);

        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost post = new HttpPost(authBaseUrl);
        Gson gson = new Gson();

        StringEntity postingString = new StringEntity(gson.toJson(req));
        post.setEntity(postingString);
        post.setHeader("Content-type", "application/json");
        HttpResponse response = httpClient.execute(post);
        Header[] cookie = response.getHeaders("Set-Cookie");
        if (cookie.length == 0)
            throw new TokenGenerationFailedException();
        String token = response.getHeaders("Set-Cookie")[0].getValue();
        token = token.replace(AUTHORIZATION, "");
        token = "Bearer " + token.substring(0, token.indexOf(';'));
        System.setProperty(TOKEN, token);
        return token;
    }

    public <T> T getApiWithCustomHeaders(String url, Class<?> responseType, HttpHeaders customHeaders) {
        T result = null;
        RestTemplate rt = restTemplate;
        if (disableSelfTokenRestTemplate) {
            rt = plainRestTemplate;
        }
        try {
            log.info("RestApiClient::getApiWithCustomHeaders()::entry url: {}", url);
            // Add custom headers to the request
            HttpEntity<Object> requestEntity = new HttpEntity<>(customHeaders);
            result = (T) rt.exchange(url, HttpMethod.GET, requestEntity, responseType).getBody();
        } catch (Exception e) {
            log.error("RestApiClient::getApiWithCustomHeaders()::error url:{} {} {}", url, e.getMessage(), e);
        }
        return result;
    }
}
