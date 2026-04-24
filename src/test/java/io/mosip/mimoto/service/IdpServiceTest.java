package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerV2DTO;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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

    private IssuerV2DTO issuerDTO;
    private Map<String, String> params;
    private final String authorizationAudience = "https://example.com/auth";



    @Before
    public void setUp() throws IOException {
        issuerDTO = new IssuerV2DTO();
        issuerDTO.setClientId("client123");
        issuerDTO.setClientAlias("clientAlias");

        params = new HashMap<>();
        params.put("code", "sampleCode");
        params.put("grant_type", "authorization_code");
        params.put("redirect_uri", "https://myapp.com/callback");
        params.put("code_verifier", "verifier123");
    }

    @Test
    public void shouldConstructTokenRequestForTheValidIssuerAndParams() throws Exception {
        when(joseUtil.getJWT(eq("client123"), any(), any(), eq("clientAlias"), any(), eq(authorizationAudience)))
                .thenReturn("jwt-token");

        HttpEntity<MultiValueMap<String, String>> httpEntity =
                idpService.constructGetTokenRequest(params, issuerDTO, authorizationAudience);

        HttpHeaders headers = httpEntity.getHeaders();
        MultiValueMap<String, String> body = httpEntity.getBody();
        assertEquals(MediaType.APPLICATION_FORM_URLENCODED, headers.getContentType());
        assertNotNull(body);
        assertAll(
                () -> assertEquals("sampleCode", body.getFirst("code")),
                () -> assertEquals("client123", body.getFirst("client_id")),
                () -> assertEquals("authorization_code", body.getFirst("grant_type")),
                () -> assertEquals("https://myapp.com/callback", body.getFirst("redirect_uri")),
                () -> assertEquals("jwt-token", body.getFirst("client_assertion")),
                () -> assertEquals("verifier123", body.getFirst("code_verifier"))
        );
    }

    @Test
    public void shouldThrowExceptionIfThereIsAnyErrorOccurredWhileFetchingP12File() throws IOException {
        String expectedExceptionMsg = "RESIDENT-APP-037 --> Private Key Entry is Missing for the alias clientAlias";
        when(joseUtil.getJWT(eq("client123"), any(), any(), eq("clientAlias"), any(), eq(authorizationAudience)))
                .thenThrow(new IssuerOnboardingException("Private Key Entry is Missing for the alias clientAlias"));

        IssuerOnboardingException actualException = assertThrows(IssuerOnboardingException.class, () ->
                idpService.constructGetTokenRequest(params, issuerDTO, authorizationAudience));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void shouldReturnTokenEndpointFromCredentialIssuerConfigurationResponse() {
        CredentialIssuerConfiguration credentialIssuerConfiguration =
                getCredentialIssuerConfigurationResponseDto("issuer1", "CredentialType1", List.of());
        String expectedTokenEndpoint = "https://dev/token";

        String actualTokenEndpoint = idpService.getTokenEndpoint(credentialIssuerConfiguration);

        assertEquals(expectedTokenEndpoint, actualTokenEndpoint);
    }

    @Test
    public void shouldThrowExceptionIfResponseIsNullWhenFetchingTokenResponse() throws Exception {
        params.put("issuer", "issuer123");

        IssuerV2DTO mockIssuer = new IssuerV2DTO();
        mockIssuer.setClientId("client123");
        mockIssuer.setClientAlias("clientAlias");

        when(issuersService.getIssuerV2Details("issuer123")).thenReturn(mockIssuer);
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

        IssuerV2DTO mockIssuer = new IssuerV2DTO();
        mockIssuer.setClientId("client123");
        mockIssuer.setClientAlias("clientAlias");

        when(issuersService.getIssuerV2Details("issuer123")).thenReturn(mockIssuer);
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

        IssuerV2DTO mockIssuer = new IssuerV2DTO();
        mockIssuer.setClientId("client123");
        mockIssuer.setClientAlias("clientAlias");

        when(issuersService.getIssuerV2Details("issuer123")).thenReturn(mockIssuer);
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

        IssuerV2DTO mockIssuer = new IssuerV2DTO();
        mockIssuer.setClientId("client123");
        mockIssuer.setClientAlias("clientAlias");

        when(issuersService.getIssuerV2Details("issuer123")).thenReturn(mockIssuer);
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
}