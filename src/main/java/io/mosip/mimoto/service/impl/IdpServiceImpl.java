package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.DpopConstants;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.VerifiableCredentialRequestDTO;
import io.mosip.mimoto.dto.dpop.DpopIssuanceSession;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.DpopIssuanceSessionService;
import io.mosip.mimoto.service.DpopProofService;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.DpopResponseHelper;
import io.mosip.mimoto.util.JoseUtil;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import static io.mosip.mimoto.exception.ErrorConstants.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class IdpServiceImpl implements IdpService {

    private static final String DPOP_HEADER = "DPoP";

    @Value("${mosip.oidc.client.assertion.type}")
    String clientAssertionType;

    @Value("${mosip.oidc.p12.filename}")
    private String fileName;

    @Value("${mosip.oidc.p12.password}")
    private String cyptoPassword;

    @Value("${mosip.oidc.p12.path}")
    String keyStorePath;

    private static final String GRANT_TYPE = "grant_type";
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String CODE_VERIFIER = "code_verifier";
    // RFC 7636 §4.1: code_verifier = 43*128unreserved; unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
    private static final String CODE_VERIFIER_PATTERN = "^[A-Za-z0-9\\-._~]{43,128}$";

    private final JoseUtil joseUtil;

    private final RestTemplate restTemplate;

    private final IssuersService issuersService;

    private final DpopIssuanceSessionService dpopIssuanceSessionService;

    private final DpopProofService dpopProofService;

    private final ObjectMapper objectMapper;

    public IdpServiceImpl(JoseUtil joseUtil, @Qualifier("restTemplate") RestTemplate restTemplate, IssuersService issuersService,
                          DpopIssuanceSessionService dpopIssuanceSessionService, DpopProofService dpopProofService,
                          ObjectMapper objectMapper) {
        this.joseUtil = joseUtil;
        this.restTemplate = restTemplate;
        this.issuersService = issuersService;
        this.dpopIssuanceSessionService = dpopIssuanceSessionService;
        this.dpopProofService = dpopProofService;
        this.objectMapper = objectMapper;
    }

    @Override
    public HttpEntity<MultiValueMap<String, String>> constructGetTokenRequest(Map<String, String> params, String issuerId, String tokenEndpoint) throws IOException, IssuerOnboardingException, ApiNotAccessibleException, InvalidIssuerIdException {
        HttpHeaders headers = new HttpHeaders();
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        validateCodeVerifier(params.get("code_verifier"));
        IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);

        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        String audience = StringUtils.hasText(issuerDTO.getAuthorization_audience())
                ? issuerDTO.getAuthorization_audience()
                : tokenEndpoint;
        String clientAssertion = joseUtil.getJWT(issuerDTO.getClient_id(), keyStorePath, fileName, issuerDTO.getClient_alias(), cyptoPassword, audience);
        map.add("code", params.get("code"));
        map.add("client_id", issuerDTO.getClient_id());
        map.add(GRANT_TYPE, params.get(GRANT_TYPE));
        map.add(REDIRECT_URI, params.get(REDIRECT_URI));
        map.add("client_assertion", clientAssertion.replace("[", "").replace("]", ""));
        map.add("client_assertion_type", clientAssertionType);
        map.add(CODE_VERIFIER, params.get(CODE_VERIFIER));

        return new HttpEntity<>(map, headers);
    }

    @Override
    public String getTokenEndpoint(String issuerId)
            throws ApiNotAccessibleException, IOException,
            AuthorizationServerWellknownResponseException,
            InvalidWellknownResponseException {
        try {
            IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
            if (StringUtils.hasText(issuerDTO.getProxy_token_endpoint())) {
                return issuerDTO.getProxy_token_endpoint();
            }
        } catch (InvalidIssuerIdException e) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Invalid issuer");
        }
        CredentialIssuerConfiguration credentialIssuerConfiguration =
                issuersService.getIssuerConfiguration(issuerId);
        return credentialIssuerConfiguration.getAuthorizationServerWellKnownResponse().getTokenEndpoint();
    }

    @Override
    public TokenResponseDTO getTokenResponse(VerifiableCredentialRequestDTO verifiableCredentialRequest) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        return getTokenResponse(convertVerifiableCredentialRequestToMap(verifiableCredentialRequest));
    }

    @Override
    public TokenResponseDTO getTokenResponse(Map<String, String> params)
            throws ApiNotAccessibleException, IOException,
            AuthorizationServerWellknownResponseException,
            InvalidWellknownResponseException {
        try {
            String issuerId = params.get("issuer");
            String codeVerifier = params.get(CODE_VERIFIER);
            if (codeVerifier == null || !codeVerifier.matches(CODE_VERIFIER_PATTERN)) {
                throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Invalid code verifier.");
            }

            String tokenEndpoint = getTokenEndpoint(issuerId);

            HttpEntity<MultiValueMap<String, String>> request =
                    constructGetTokenRequest(params, issuerId, tokenEndpoint);

            TokenResponseDTO response = restTemplate.postForObject(
                    tokenEndpoint,
                    request,
                    TokenResponseDTO.class
            );

            if (response == null) {
                throw new IdpException("Exception occurred while performing the authorization");
            }

            return response;

        } catch (InvalidIssuerIdException e) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Invalid issuer");

        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.BAD_REQUEST) {
                throw new InvalidRequestException(
                        INVALID_REQUEST.getErrorCode(),
                        "Request failed due to invalid input detected by an external service."
                );
            }
            throw e;
        }
    }



    @Override
    public ResponseEntity<String> getTokenResponseV2(Map<String, String> params, String dpopProof)
            throws ApiNotAccessibleException, IOException,
            AuthorizationServerWellknownResponseException,
            InvalidWellknownResponseException,
            IssuerOnboardingException {

        try {
            String issuerId = params.get("issuer");
            String tokenEndpoint = getTokenEndpoint(issuerId);

            HttpEntity<MultiValueMap<String, String>> request =
                    constructGetTokenRequest(params, issuerId, tokenEndpoint);

            HttpHeaders headers = new HttpHeaders();
            headers.addAll(request.getHeaders());

            if (StringUtils.hasText(dpopProof)) {
                headers.set(DPOP_HEADER, dpopProof);
            }

            HttpEntity<MultiValueMap<String, String>> requestWithDpop =
                    new HttpEntity<>(request.getBody(), headers);

            return restTemplate.exchange(
                    tokenEndpoint,
                    HttpMethod.POST,
                    requestWithDpop,
                    String.class
            );

        } catch (InvalidIssuerIdException e) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Invalid issuer");

        } catch (HttpStatusCodeException e) {
            return ResponseEntity.status(e.getStatusCode())
                    .headers(e.getResponseHeaders())
                    .body(e.getResponseBodyAsString());
        }
    }

    @Override
    public TokenResponseDTO exchangeAndBindToken(Map<String, String> params, HttpSession httpSession)
            throws ApiNotAccessibleException, IOException,
            AuthorizationServerWellknownResponseException,
            InvalidWellknownResponseException,
            IssuerOnboardingException {
        DpopIssuanceSession issuanceSession = dpopIssuanceSessionService.find(httpSession, params.get("state"));
        if (issuanceSession == null) {
            return null;
        }
        try {
            String issuerId = params.get("issuer");
            String tokenEndpoint = getTokenEndpoint(issuerId);

            HttpEntity<MultiValueMap<String, String>> request =
                    constructGetTokenRequest(params, issuerId, tokenEndpoint);
            ResponseEntity<String> asResponse =
                    exchangeTokenWithServerDpop(tokenEndpoint, request, issuanceSession, httpSession);
            if (!asResponse.getStatusCode().is2xxSuccessful()) {
                Object body = DpopResponseHelper.normalizeOAuthErrorBody(asResponse.getBody());
                String description = asResponse.getBody();
                if (body instanceof Map<?, ?> map && map.get("error_description") != null) {
                    description = String.valueOf(map.get("error_description"));
                } else if (body instanceof Map<?, ?> map && map.get("error") != null) {
                    description = String.valueOf(map.get("error"));
                }
                throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                        "Token exchange failed: " + description);
            }
            return dpopIssuanceSessionService.tokenFromSession(httpSession, params.get("state"));
        } catch (InvalidIssuerIdException e) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Invalid issuer");
        }
    }

    private ResponseEntity<String> exchangeTokenWithServerDpop(String tokenEndpoint,
                                                               HttpEntity<MultiValueMap<String, String>> request,
                                                               DpopIssuanceSession issuanceSession,
                                                               HttpSession httpSession) throws IOException {
        ResponseEntity<String> asResponse = postTokenWithProof(tokenEndpoint, request, issuanceSession, issuanceSession.getAsDpopNonce());
        if (isUseDpopNonce(asResponse)) {
            String nonce = asResponse.getHeaders().getFirst(DpopConstants.DPOP_NONCE_HEADER);
            issuanceSession.setAsDpopNonce(nonce);
            dpopIssuanceSessionService.store(httpSession, issuanceSession);
            asResponse = postTokenWithProof(tokenEndpoint, request, issuanceSession, nonce);
        }
        if (asResponse.getStatusCode().is2xxSuccessful() && StringUtils.hasText(asResponse.getBody())) {
            TokenResponseDTO token = objectMapper.readValue(asResponse.getBody(), TokenResponseDTO.class);
            issuanceSession.setAccessToken(token.getAccess_token());
            issuanceSession.setTokenType(StringUtils.hasText(token.getToken_type())
                    ? token.getToken_type()
                    : DpopConstants.DPOP_TOKEN_TYPE);
            issuanceSession.setCNonce(token.getC_nonce());
            dpopIssuanceSessionService.store(httpSession, issuanceSession);
        }
        return asResponse;
    }

    private ResponseEntity<String> postTokenWithProof(String tokenEndpoint,
                                                      HttpEntity<MultiValueMap<String, String>> request,
                                                      DpopIssuanceSession issuanceSession,
                                                      String nonce) {
        HttpHeaders headers = new HttpHeaders();
        headers.addAll(request.getHeaders());
        headers.set(DPOP_HEADER, dpopProofService.createProof(issuanceSession, issuanceSession.getTokenHtu(), "POST", nonce, null));
        try {
            return restTemplate.exchange(
                    tokenEndpoint,
                    HttpMethod.POST,
                    new HttpEntity<>(request.getBody(), headers),
                    String.class
            );
        } catch (HttpStatusCodeException e) {
            return ResponseEntity.status(e.getStatusCode())
                    .headers(e.getResponseHeaders())
                    .body(e.getResponseBodyAsString());
        }
    }

    private static boolean isUseDpopNonce(ResponseEntity<String> response) {
        if (response.getStatusCode().is2xxSuccessful()) {
            return false;
        }
        String nonce = response.getHeaders().getFirst(DpopConstants.DPOP_NONCE_HEADER);
        if (!StringUtils.hasText(nonce)) {
            return false;
        }
        Object body = DpopResponseHelper.normalizeOAuthErrorBody(response.getBody());
        if (body instanceof Map<?, ?> map) {
            return DpopConstants.USE_DPOP_NONCE_ERROR.equals(String.valueOf(map.get("error")));
        }
        return StringUtils.hasText(response.getBody()) && response.getBody().contains(DpopConstants.USE_DPOP_NONCE_ERROR);
    }

    private void validateCodeVerifier(String codeVerifier) {
        if (codeVerifier == null || !codeVerifier.matches(CODE_VERIFIER_PATTERN)) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Invalid code verifier.");
        }
    }

    private Map<String, String> convertVerifiableCredentialRequestToMap(VerifiableCredentialRequestDTO verifiableCredentialRequest) {
        Map<String, String> params = new HashMap<>();
        params.put("code", verifiableCredentialRequest.getCode());
        params.put("issuer", verifiableCredentialRequest.getIssuer());
        return params;
    }

}
