package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.AuthorizationServerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.service.impl.IdpServiceImpl;
import io.mosip.mimoto.util.JoseUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class IdpServiceV2Test {

    @InjectMocks
    IdpServiceImpl idpService;

    @Mock
    JoseUtil joseUtil;

    @Mock
    RestTemplate restTemplate;

    @Mock
    IssuersService issuersService;

    private final String tokenEndpoint = "https://as.example.com/token";
    private Map<String, String> params;

    @Before
    public void setUp() throws Exception {
        params = new HashMap<>();
        params.put("issuer", "issuer1");
        params.put("code", "auth-code");
        params.put("grant_type", "authorization_code");
        params.put("redirect_uri", "https://wallet/redirect");
        params.put("code_verifier", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");

        IssuerDTO issuerDTO = new IssuerDTO();
        issuerDTO.setClient_id("client-1");
        issuerDTO.setClient_alias("alias-1");

        AuthorizationServerWellKnownResponse asWellKnown = new AuthorizationServerWellKnownResponse();
        asWellKnown.setTokenEndpoint(tokenEndpoint);
        CredentialIssuerConfiguration issuerConfiguration = new CredentialIssuerConfiguration();
        issuerConfiguration.setAuthorizationServerWellKnownResponse(asWellKnown);

        when(issuersService.getIssuerDetails("issuer1")).thenReturn(issuerDTO);
        when(issuersService.getIssuerConfiguration("issuer1")).thenReturn(issuerConfiguration);
        when(joseUtil.getJWT(any(), any(), any(), any(), any(), any())).thenReturn("signed-client-assertion");
    }

    @Test
    public void shouldPassThroughSuccessResponseAsIs() throws Exception {
        String body = "{\"access_token\":\"abc\",\"token_type\":\"DPoP\"}";
        ResponseEntity<String> asResponse = ResponseEntity.status(HttpStatus.OK).body(body);
        when(restTemplate.exchange(eq(tokenEndpoint), eq(HttpMethod.POST), any(), eq(String.class)))
                .thenReturn(asResponse);

        ResponseEntity<String> result = idpService.getTokenResponseV2(params, "dpop-proof-jwt");

        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertEquals(body, result.getBody());
    }

    @Test
    public void shouldPassThroughUseDpopNonceErrorWithNonceHeaderAsIs() throws Exception {
        String errorBody = "{\"error\":\"use_dpop_nonce\",\"error_description\":\"nonce required\"}";
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("DPoP-Nonce", "server-issued-nonce-123");
        HttpClientErrorException exception = HttpClientErrorException.create(
                HttpStatus.BAD_REQUEST, "Bad Request", responseHeaders,
                errorBody.getBytes(), null);
        when(restTemplate.exchange(eq(tokenEndpoint), eq(HttpMethod.POST), any(), eq(String.class)))
                .thenThrow(exception);

        ResponseEntity<String> result = idpService.getTokenResponseV2(params, "dpop-proof-jwt");

        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertEquals(errorBody, result.getBody());
        assertEquals("server-issued-nonce-123", result.getHeaders().getFirst("DPoP-Nonce"));
    }

    @Test
    public void shouldPassThroughWwwAuthenticateHeaderOnUnauthorized() throws Exception {
        String errorBody = "{\"error\":\"invalid_dpop_proof\"}";
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\"");
        responseHeaders.add("DPoP-Nonce", "nonce-on-401");
        HttpClientErrorException exception = HttpClientErrorException.create(
                HttpStatus.UNAUTHORIZED, "Unauthorized", responseHeaders,
                errorBody.getBytes(), null);
        when(restTemplate.exchange(eq(tokenEndpoint), eq(HttpMethod.POST), any(), eq(String.class)))
                .thenThrow(exception);

        ResponseEntity<String> result = idpService.getTokenResponseV2(params, "dpop-proof-jwt");

        assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
        assertEquals(errorBody, result.getBody());
        assertEquals("DPoP error=\"invalid_dpop_proof\"", result.getHeaders().getFirst("WWW-Authenticate"));
        assertEquals("nonce-on-401", result.getHeaders().getFirst("DPoP-Nonce"));
    }
}
