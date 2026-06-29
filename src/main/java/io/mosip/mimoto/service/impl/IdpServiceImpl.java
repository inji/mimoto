package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.VerifiableCredentialRequestDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.JoseUtil;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpStatus;

import static io.mosip.mimoto.exception.ErrorConstants.*;

import java.io.IOException;
import java.util.HashMap;
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

    private final JoseUtil joseUtil;

    private final RestTemplate restTemplate;

    private final IssuersService issuersService;

    public IdpServiceImpl(JoseUtil joseUtil, @Qualifier("restTemplate") RestTemplate restTemplate, IssuersService issuersService) {
        this.joseUtil = joseUtil;
        this.restTemplate = restTemplate;
        this.issuersService = issuersService;
    }

    @Override
    public HttpEntity<MultiValueMap<String, String>> constructGetTokenRequest(Map<String, String> params, IssuerDTO issuerDTO, String authorizationAudience) throws IOException, IssuerOnboardingException {
        HttpHeaders headers = new HttpHeaders();
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();

        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        String clientAssertion = joseUtil.getJWT(issuerDTO.getClient_id(), keyStorePath, fileName, issuerDTO.getClient_alias(), cyptoPassword, authorizationAudience);
        map.add("code", params.get("code"));
        map.add("client_id", issuerDTO.getClient_id());
        map.add("grant_type", params.get("grant_type"));
        map.add("redirect_uri", params.get("redirect_uri"));
        map.add("client_assertion", clientAssertion.replace("[", "").replace("]", ""));
        map.add("client_assertion_type", clientAssertionType);
        map.add("code_verifier", params.get("code_verifier"));

        return new HttpEntity<>(map, headers);
    }

    @Override
    public String getTokenEndpoint(CredentialIssuerConfiguration credentialIssuerConfiguration) {
        return credentialIssuerConfiguration.getAuthorizationServerWellKnownResponse().getTokenEndpoint();
    }

    @Override
    public TokenResponseDTO getTokenResponse(VerifiableCredentialRequestDTO verifiableCredentialRequest) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        return getTokenResponse(convertVerifiableCredentialRequestToMap(verifiableCredentialRequest));
    }

    @Override
    public TokenResponseDTO getTokenResponse(Map<String, String> params) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        try{
            String issuerId = params.get("issuer");
            String codeVerifier = params.get("code_verifier");
            if (codeVerifier == null || !codeVerifier.matches("^[A-Za-z0-9\\-._~]{43,128}$")) {
                throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Invalid code verifier.");
            }

            IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
            CredentialIssuerConfiguration credentialIssuerConfiguration = issuersService.getIssuerConfiguration(issuerId);
            String tokenEndpoint = getTokenEndpoint(credentialIssuerConfiguration);
            HttpEntity<MultiValueMap<String, String>> request = constructGetTokenRequest(params, issuerDTO, tokenEndpoint);
            TokenResponseDTO response = restTemplate.postForObject(tokenEndpoint, request, TokenResponseDTO.class);
            if (response == null) {
                throw new IdpException("Exception occurred while performing the authorization");
            }
            return response;
        } catch (InvalidIssuerIdException e) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Invalid issuer");
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.BAD_REQUEST) {
                throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Request failed due to invalid input detected by an external service.");
            } else {
                throw e;
            }
        }
    }


    @Override
    public ResponseEntity<String> getTokenResponseV2(Map<String, String> params, String dpopProof) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException, IssuerOnboardingException {
        String issuerId = params.get("issuer");
        IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
        CredentialIssuerConfiguration credentialIssuerConfiguration = issuersService.getIssuerConfiguration(issuerId);
        String tokenEndpoint = getTokenEndpoint(credentialIssuerConfiguration);

        HttpEntity<MultiValueMap<String, String>> request = constructGetTokenRequest(params, issuerDTO, tokenEndpoint);
        HttpHeaders headers = new HttpHeaders();
        headers.addAll(request.getHeaders());
        if (StringUtils.hasText(dpopProof)) {
            headers.set(DPOP_HEADER, dpopProof);
        }
        HttpEntity<MultiValueMap<String, String>> requestWithDpop = new HttpEntity<>(request.getBody(), headers);

        try {
            return restTemplate.exchange(tokenEndpoint, HttpMethod.POST, requestWithDpop, String.class);
        } catch (HttpStatusCodeException e) {
            return ResponseEntity.status(e.getStatusCode())
                    .headers(e.getResponseHeaders())
                    .body(e.getResponseBodyAsString());
        }
    }

    private Map<String, String> convertVerifiableCredentialRequestToMap(VerifiableCredentialRequestDTO verifiableCredentialRequest) {
        Map<String, String> params = new HashMap<>();
        params.put("code", verifiableCredentialRequest.getCode());
        params.put("redirect_uri", verifiableCredentialRequest.getRedirectUri());
        params.put("grant_type", verifiableCredentialRequest.getGrantType());
        params.put("code_verifier", verifiableCredentialRequest.getCodeVerifier());
        params.put("issuer", verifiableCredentialRequest.getIssuer());

        return params;
    }

}
