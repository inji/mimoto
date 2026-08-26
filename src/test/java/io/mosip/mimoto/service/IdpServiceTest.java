package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.VerifiableCredentialRequestDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.AuthorizationServerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.exception.IdpException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.IssuerOnboardingException;
import io.mosip.mimoto.service.impl.IdpServiceImpl;
import io.mosip.mimoto.util.JoseUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.util.TestUtilities.getCredentialIssuerConfigurationResponseDto;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class IdpServiceTest {
    @InjectMocks
    private IdpServiceImpl idpService;

    @Mock
    JoseUtil joseUtil;

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private IssuersService issuersService;

    @Mock
    private CredentialIssuerConfiguration credentialIssuerConfiguration;

    @Mock
    private AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse;

    @Mock
    private TokenResponseDTO tokenResponseDTO;

    private Map<String, String> params;
    private final String authorizationAudience = "https://example.com/auth";



    @Before
    public void setUp() throws IOException {
        params = new HashMap<>();
        params.put("issuer", "issuer123");
        params.put("code", "sampleCode");
        params.put("grant_type", "authorization_code");
        params.put("redirect_uri", "https://myapp.com/callback");
        params.put("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    }

    @Test
    public void shouldConstructTokenRequestForTheValidIssuerAndParams() throws Exception {
        IssuerDTO issuerDTO = new IssuerDTO();
        issuerDTO.setClient_id("client123");
        issuerDTO.setClient_alias("clientAlias");

        when(issuersService.getIssuerDetails("issuer123")).thenReturn(issuerDTO);
        when(joseUtil.getJWT(eq("client123"), any(), any(), eq("clientAlias"), any(), eq(authorizationAudience)))
                .thenReturn("jwt-token");

        HttpEntity<MultiValueMap<String, String>> httpEntity =
                idpService.constructGetTokenRequest(params, "issuer123", authorizationAudience);

        HttpHeaders headers = httpEntity.getHeaders();
        MultiValueMap<String, String> body = httpEntity.getBody();
        assertEquals(MediaType.APPLICATION_FORM_URLENCODED, headers.getContentType());
        assertEquals(List.of(MediaType.APPLICATION_JSON), headers.getAccept());
        assertNotNull(body);
        assertAll(
                () -> assertEquals("sampleCode", body.getFirst("code")),
                () -> assertEquals("client123", body.getFirst("client_id")),
                () -> assertEquals("authorization_code", body.getFirst("grant_type")),
                () -> assertEquals("https://myapp.com/callback", body.getFirst("redirect_uri")),
                () -> assertEquals("jwt-token", body.getFirst("client_assertion")),
                () -> assertEquals("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", body.getFirst("code_verifier"))
        );
    }

    @Test
    public void shouldThrowExceptionIfThereIsAnyErrorOccurredWhileFetchingP12File() throws Exception {
        IssuerDTO issuerDTO = new IssuerDTO();
        issuerDTO.setClient_id("client123");
        issuerDTO.setClient_alias("clientAlias");

        String expectedExceptionMsg = "RESIDENT-APP-037 --> Private Key Entry is Missing for the alias clientAlias";
        when(issuersService.getIssuerDetails("issuer123")).thenReturn(issuerDTO);
        when(joseUtil.getJWT(eq("client123"), any(), any(), eq("clientAlias"), any(), eq(authorizationAudience)))
                .thenThrow(new IssuerOnboardingException("Private Key Entry is Missing for the alias clientAlias"));

        IssuerOnboardingException actualException = assertThrows(IssuerOnboardingException.class, () ->
                idpService.constructGetTokenRequest(params, "issuer123", authorizationAudience));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void shouldUseAuthorizationAudienceForClientAssertionWhenConfigured() throws Exception {
        String proxyTokenEndpoint = "http://localhost:8088/v1/esignet/oauth/v2/token";
        String audience = "http://localhost:3000/v1/esignet/oauth/v2/token";
        IssuerDTO issuerDTO = new IssuerDTO();
        issuerDTO.setClient_id("client123");
        issuerDTO.setClient_alias("clientAlias");
        issuerDTO.setAuthorization_audience(audience);

        when(issuersService.getIssuerDetails("issuer123")).thenReturn(issuerDTO);
        when(joseUtil.getJWT(eq("client123"), any(), any(), eq("clientAlias"), any(), eq(audience)))
                .thenReturn("jwt-token");

        idpService.constructGetTokenRequest(params, "issuer123", proxyTokenEndpoint);

        verify(joseUtil).getJWT(eq("client123"), any(), any(), eq("clientAlias"), any(), eq(audience));
        verify(joseUtil, never()).getJWT(eq("client123"), any(), any(), eq("clientAlias"), any(), eq(proxyTokenEndpoint));
    }

    @Test
    public void shouldReturnTokenEndpointFromCredentialIssuerConfigurationResponse() throws Exception {
        CredentialIssuerConfiguration credentialIssuerConfiguration =
                getCredentialIssuerConfigurationResponseDto("issuer1", "CredentialType1", List.of());
        String expectedTokenEndpoint = "https://dev/token";

        when(issuersService.getIssuerDetails("issuer1")).thenReturn(new IssuerDTO());
        when(issuersService.getIssuerConfiguration("issuer1")).thenReturn(credentialIssuerConfiguration);

        String actualTokenEndpoint = idpService.getTokenEndpoint("issuer1");

        assertEquals(expectedTokenEndpoint, actualTokenEndpoint);
    }

    @Test
    public void shouldReturnProxyTokenEndpointWhenConfigured() throws Exception {
        String proxyTokenEndpoint = "http://localhost:8088/v1/esignet/oauth/v2/token";
        IssuerDTO issuerDTO = new IssuerDTO();
        issuerDTO.setProxy_token_endpoint(proxyTokenEndpoint);

        when(issuersService.getIssuerDetails("issuer1")).thenReturn(issuerDTO);

        String actualTokenEndpoint = idpService.getTokenEndpoint("issuer1");

        assertEquals(proxyTokenEndpoint, actualTokenEndpoint);
        verify(issuersService, never()).getIssuerConfiguration("issuer1");
    }

    @Test
    public void shouldThrowExceptionIfResponseIsNullWhenFetchingTokenResponse() throws Exception {
        params.put("issuer", "issuer123");

        IssuerDTO mockIssuer = new IssuerDTO();
        mockIssuer.setClient_id("client123");
        mockIssuer.setClient_alias("clientAlias");

        when(issuersService.getIssuerDetails("issuer123")).thenReturn(mockIssuer);
        when(issuersService.getIssuerConfiguration("issuer123")).thenReturn(credentialIssuerConfiguration);

        when(credentialIssuerConfiguration.getAuthorizationServerWellKnownResponse())
                .thenReturn(authorizationServerWellKnownResponse);
        when(authorizationServerWellKnownResponse.getTokenEndpoint())
                .thenReturn("https://example.com/token");

        when(joseUtil.getJWT(eq("client123"), any(), any(), eq("clientAlias"), any(), eq("https://example.com/token")))
                .thenReturn("jwt-token");

        when(restTemplate.postForObject(eq("https://example.com/token"), any(HttpEntity.class), eq(TokenResponseDTO.class)))
                .thenReturn(null);

        params.put("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        IdpException ex = assertThrows(IdpException.class, () ->
                idpService.getTokenResponse(params));

        assertEquals("RESIDENT-APP-034 --> Exception occurred while performing the authorization", ex.getMessage());
    }

    @Test
    public void shouldReturnTokenResponseForValidTokenEndpoint() throws Exception {
        params.put("issuer", "issuer123");

        IssuerDTO mockIssuer = new IssuerDTO();
        mockIssuer.setClient_id("client123");
        mockIssuer.setClient_alias("clientAlias");

        when(issuersService.getIssuerDetails("issuer123")).thenReturn(mockIssuer);
        when(issuersService.getIssuerConfiguration("issuer123")).thenReturn(credentialIssuerConfiguration);
        when(credentialIssuerConfiguration.getAuthorizationServerWellKnownResponse())
                .thenReturn(authorizationServerWellKnownResponse);
        when(authorizationServerWellKnownResponse.getTokenEndpoint())
                .thenReturn("https://example.com/token");

        when(joseUtil.getJWT(eq("client123"), any(), any(), eq("clientAlias"), any(), eq("https://example.com/token")))
                .thenReturn("jwt-token");

        when(restTemplate.postForObject(eq("https://example.com/token"), any(HttpEntity.class), eq(TokenResponseDTO.class)))
                .thenReturn(tokenResponseDTO);

        params.put("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        TokenResponseDTO response = idpService.getTokenResponse(params);

        assertNotNull(response);
        assertEquals(tokenResponseDTO, response);
    }

    @Test
    public void shouldThrowInvalidRequestExceptionOnBadRequestFromTokenEndpoint() throws Exception {
        params.put("issuer", "issuer123");

        IssuerDTO mockIssuer = new IssuerDTO();
        mockIssuer.setClient_id("client123");
        mockIssuer.setClient_alias("clientAlias");

        when(issuersService.getIssuerDetails("issuer123")).thenReturn(mockIssuer);
        when(issuersService.getIssuerConfiguration("issuer123")).thenReturn(credentialIssuerConfiguration);
        when(credentialIssuerConfiguration.getAuthorizationServerWellKnownResponse())
                .thenReturn(authorizationServerWellKnownResponse);
        when(authorizationServerWellKnownResponse.getTokenEndpoint())
                .thenReturn("https://example.com/token");
        when(joseUtil.getJWT(eq("client123"), any(), any(), eq("clientAlias"), any(), eq("https://example.com/token")))
                .thenReturn("jwt-token");

        HttpClientErrorException badRequestException = HttpClientErrorException.create(
                HttpStatus.BAD_REQUEST, "Bad Request", null, null, null);

        when(restTemplate.postForObject(eq("https://example.com/token"), any(HttpEntity.class), eq(TokenResponseDTO.class)))
                .thenThrow(badRequestException);

        params.put("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        InvalidRequestException ex = assertThrows(InvalidRequestException.class, () ->
                idpService.getTokenResponse(params));

        assertEquals("invalid_request --> Request failed due to invalid input detected by an external service.", ex.getMessage());
    }

    @Test
    public void shouldReturnTokenResponseForVerifiableCredentialRequestDTO() throws Exception {
        VerifiableCredentialRequestDTO requestDTO = new VerifiableCredentialRequestDTO();
        requestDTO.setCode("sampleCode");
        requestDTO.setRedirectUri("https://myapp.com/callback");
        requestDTO.setGrantType("authorization_code");
        requestDTO.setCodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        requestDTO.setIssuer("issuer123");

        IssuerDTO mockIssuer = new IssuerDTO();
        mockIssuer.setClient_id("client123");
        mockIssuer.setClient_alias("clientAlias");

        when(issuersService.getIssuerDetails("issuer123")).thenReturn(mockIssuer);
        when(issuersService.getIssuerConfiguration("issuer123")).thenReturn(credentialIssuerConfiguration);
        when(credentialIssuerConfiguration.getAuthorizationServerWellKnownResponse())
                .thenReturn(authorizationServerWellKnownResponse);
        when(authorizationServerWellKnownResponse.getTokenEndpoint())
                .thenReturn("https://example.com/token");
        when(joseUtil.getJWT(eq("client123"), any(), any(), eq("clientAlias"), any(), eq("https://example.com/token")))
                .thenReturn("jwt-token");
        when(restTemplate.postForObject(eq("https://example.com/token"), any(HttpEntity.class), eq(TokenResponseDTO.class)))
                .thenReturn(tokenResponseDTO);

        TokenResponseDTO response = idpService.getTokenResponse(requestDTO);

        assertNotNull(response);
        assertEquals(tokenResponseDTO, response);
    }

    @Test
    public void shouldPassThroughSuccessResponseAsIsForV2TokenResponse() throws Exception {
        String tokenEndpoint = "https://as.example.com/token";
        String body = "{\"access_token\":\"abc\",\"token_type\":\"DPoP\"}";
        ResponseEntity<String> asResponse = ResponseEntity.status(HttpStatus.OK).body(body);

        setupV2TokenEndpoint(tokenEndpoint);
        when(restTemplate.exchange(eq(tokenEndpoint), eq(HttpMethod.POST), any(), eq(String.class)))
                .thenReturn(asResponse);

        ResponseEntity<String> result = idpService.getTokenResponseV2(params, "dpop-proof-jwt");

        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertEquals(body, result.getBody());
    }

    @Test
    public void shouldPassThroughUseDpopNonceErrorWithNonceHeaderAsIsForV2TokenResponse() throws Exception {
        String tokenEndpoint = "https://as.example.com/token";
        String errorBody = "{\"error\":\"use_dpop_nonce\",\"error_description\":\"nonce required\"}";
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("DPoP-Nonce", "server-issued-nonce-123");
        HttpClientErrorException exception = HttpClientErrorException.create(
                HttpStatus.BAD_REQUEST, "Bad Request", responseHeaders,
                errorBody.getBytes(), null);

        setupV2TokenEndpoint(tokenEndpoint);
        when(restTemplate.exchange(eq(tokenEndpoint), eq(HttpMethod.POST), any(), eq(String.class)))
                .thenThrow(exception);

        ResponseEntity<String> result = idpService.getTokenResponseV2(params, "dpop-proof-jwt");

        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertEquals(errorBody, result.getBody());
        assertEquals("server-issued-nonce-123", result.getHeaders().getFirst("DPoP-Nonce"));
    }

    @Test
    public void shouldPassThroughWwwAuthenticateHeaderOnUnauthorizedForV2TokenResponse() throws Exception {
        String tokenEndpoint = "https://as.example.com/token";
        String errorBody = "{\"error\":\"invalid_dpop_proof\"}";
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\"");
        responseHeaders.add("DPoP-Nonce", "nonce-on-401");
        HttpClientErrorException exception = HttpClientErrorException.create(
                HttpStatus.UNAUTHORIZED, "Unauthorized", responseHeaders,
                errorBody.getBytes(), null);

        setupV2TokenEndpoint(tokenEndpoint);
        when(restTemplate.exchange(eq(tokenEndpoint), eq(HttpMethod.POST), any(), eq(String.class)))
                .thenThrow(exception);

        ResponseEntity<String> result = idpService.getTokenResponseV2(params, "dpop-proof-jwt");

        assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
        assertEquals(errorBody, result.getBody());
        assertEquals("DPoP error=\"invalid_dpop_proof\"", result.getHeaders().getFirst("WWW-Authenticate"));
        assertEquals("nonce-on-401", result.getHeaders().getFirst("DPoP-Nonce"));
    }

    private void setupV2TokenEndpoint(String tokenEndpoint) throws Exception {
        IssuerDTO issuerDTO = new IssuerDTO();
        issuerDTO.setClient_id("client123");
        issuerDTO.setClient_alias("clientAlias");

        when(issuersService.getIssuerDetails("issuer123")).thenReturn(issuerDTO);
        when(issuersService.getIssuerConfiguration("issuer123")).thenReturn(credentialIssuerConfiguration);
        when(credentialIssuerConfiguration.getAuthorizationServerWellKnownResponse())
                .thenReturn(authorizationServerWellKnownResponse);
        when(authorizationServerWellKnownResponse.getTokenEndpoint())
                .thenReturn(tokenEndpoint);
        when(joseUtil.getJWT(eq("client123"), any(), any(), eq("clientAlias"), any(), eq(tokenEndpoint)))
                .thenReturn("jwt-token");
    }
}
