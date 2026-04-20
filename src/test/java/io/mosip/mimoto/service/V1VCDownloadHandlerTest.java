package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.CredentialProcessingException;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.service.impl.V1VCDownloadHandler;
import io.mosip.mimoto.util.RestApiClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class V1VCDownloadHandlerTest {

    private static final String CREDENTIAL_ISSUER = "https://credential-issuer.example.com";
    private static final String CREDENTIAL_ENDPOINT = "https://credential-issuer.example.com/credential";
    private static final String NONCE_ENDPOINT = "https://credential-issuer.example.com/nonce";
    private static final String CREDENTIAL_CONFIG_ID = "SD_JWT_VC_example_in_OpenID4VCI";
    private static final String FORMAT = "dc+sd-jwt";
    private static final String ISSUER_ID = "issuer-123";
    private static final String CLIENT_ID = "mimoto-oidc-client";
    private static final String ACCESS_TOKEN = "valid-access-token";
    private static final String WALLET_ID = "wallet-1";
    private static final String BASE64_KEY = "base64-encoded-wallet-key";

    @Mock
    private V1CredentialRequestService v1CredentialRequestService;
    @Mock
    private RestApiClient restApiClient;
    @InjectMocks
    private V1VCDownloadHandler handler;

    private IssuerDTO issuerDTO;
    private CredentialIssuerWellKnownResponse wellKnownResponse;
    private TokenResponseDTO tokenResponse;

    @BeforeEach
    void setUp() {
        issuerDTO = new IssuerDTO();
        issuerDTO.setIssuer_id(ISSUER_ID);
        issuerDTO.setClient_id(CLIENT_ID);

        ProofTypesSupported proofTypesSupported = new ProofTypesSupported();
        proofTypesSupported.setProofSigningAlgValuesSupported(List.of("ES256"));

        CredentialsSupportedResponse credSupported = new CredentialsSupportedResponse();
        credSupported.setFormat(FORMAT);
        credSupported.setScope(CREDENTIAL_CONFIG_ID);
        credSupported.setVct(CREDENTIAL_CONFIG_ID);
        credSupported.setProofTypesSupported(Map.of("jwt", proofTypesSupported));

        wellKnownResponse = new CredentialIssuerWellKnownResponse();
        wellKnownResponse.setCredentialIssuer(CREDENTIAL_ISSUER);
        wellKnownResponse.setCredentialEndPoint(CREDENTIAL_ENDPOINT);
        wellKnownResponse.setNonceEndpoint(NONCE_ENDPOINT);
        wellKnownResponse.setCredentialConfigurationsSupported(Map.of(CREDENTIAL_CONFIG_ID, credSupported));

        tokenResponse = new TokenResponseDTO();
        tokenResponse.setAccess_token(ACCESS_TOKEN);
    }

    private V1VCCredentialRequest buildRequest(String jwtToken) {
        return V1VCCredentialRequest.builder()
                .credentialConfigurationId(CREDENTIAL_CONFIG_ID)
                .proofs(Map.of("jwt", List.of(jwtToken)))
                .build();
    }

    @Test
    void shouldReturnVCCredentialResponseOnSuccessfulDownload() throws Exception {
        V1VCCredentialRequest request = buildRequest("jwt-token");

        when(v1CredentialRequestService.buildRequest(eq(issuerDTO), eq(CREDENTIAL_CONFIG_ID),
                eq(wellKnownResponse), isNull(), isNull(), eq(false)))
                .thenReturn(request);

        V1VCCredentialResponse mockResponse = V1VCCredentialResponse.builder()
                .credentials(List.of("eyJhbGciOiJFUzI1NiJ9.credential-payload.signature"))
                .build();

        when(restApiClient.postApiWithErrorResponse(eq(CREDENTIAL_ENDPOINT), eq(MediaType.APPLICATION_JSON),
                eq(request), eq(V1VCCredentialResponse.class), eq(ACCESS_TOKEN)))
                .thenReturn(mockResponse);

        VCCredentialResponse result = handler.downloadCredential(issuerDTO, CREDENTIAL_CONFIG_ID,
                wellKnownResponse, tokenResponse, null, null, false);

        assertNotNull(result);
        assertEquals(FORMAT, result.getFormat());
        assertEquals("eyJhbGciOiJFUzI1NiJ9.credential-payload.signature", result.getCredential());
    }

    @Test
    void shouldReturnFirstCredentialWhenResponseContainsMultiple() throws Exception {
        V1VCCredentialRequest request = buildRequest("jwt-token");

        when(v1CredentialRequestService.buildRequest(eq(issuerDTO), eq(CREDENTIAL_CONFIG_ID),
                eq(wellKnownResponse), isNull(), isNull(), eq(false)))
                .thenReturn(request);

        V1VCCredentialResponse mockResponse = V1VCCredentialResponse.builder()
                .credentials(List.of("first-credential", "second-credential", "third-credential"))
                .build();

        when(restApiClient.postApiWithErrorResponse(eq(CREDENTIAL_ENDPOINT), eq(MediaType.APPLICATION_JSON),
                eq(request), eq(V1VCCredentialResponse.class), eq(ACCESS_TOKEN)))
                .thenReturn(mockResponse);

        VCCredentialResponse result = handler.downloadCredential(issuerDTO, CREDENTIAL_CONFIG_ID,
                wellKnownResponse, tokenResponse, null, null, false);

        assertNotNull(result);
        assertEquals("first-credential", result.getCredential());
    }

    @Test
    void shouldPassWalletIdAndBase64KeyForLoginFlow() throws Exception {
        V1VCCredentialRequest request = buildRequest("jwt-login-token");

        when(v1CredentialRequestService.buildRequest(eq(issuerDTO), eq(CREDENTIAL_CONFIG_ID),
                eq(wellKnownResponse), eq(WALLET_ID), eq(BASE64_KEY), eq(true)))
                .thenReturn(request);

        V1VCCredentialResponse mockResponse = V1VCCredentialResponse.builder()
                .credentials(List.of("login-credential-data"))
                .build();

        when(restApiClient.postApiWithErrorResponse(eq(CREDENTIAL_ENDPOINT), eq(MediaType.APPLICATION_JSON),
                eq(request), eq(V1VCCredentialResponse.class), eq(ACCESS_TOKEN)))
                .thenReturn(mockResponse);

        VCCredentialResponse result = handler.downloadCredential(issuerDTO, CREDENTIAL_CONFIG_ID,
                wellKnownResponse, tokenResponse, WALLET_ID, BASE64_KEY, true);

        assertNotNull(result);
        assertEquals(FORMAT, result.getFormat());
        assertEquals("login-credential-data", result.getCredential());
        verify(v1CredentialRequestService).buildRequest(eq(issuerDTO), eq(CREDENTIAL_CONFIG_ID),
                eq(wellKnownResponse), eq(WALLET_ID), eq(BASE64_KEY), eq(true));
    }

    @Test
    void shouldThrowCredentialProcessingExceptionWhenBuildRequestFails() throws Exception {
        when(v1CredentialRequestService.buildRequest(any(), anyString(), any(), any(), any(), anyBoolean()))
                .thenThrow(new RuntimeException("Build failed"));

        assertThrows(CredentialProcessingException.class, () ->
                handler.downloadCredential(issuerDTO, CREDENTIAL_CONFIG_ID,
                        wellKnownResponse, tokenResponse, null, null, false));
    }

    @Test
    void shouldRetryWithFreshNonceWhenFirstAttemptReturnsInvalidNonce() throws Exception {
        V1VCCredentialRequest firstRequest = buildRequest("jwt-token-1");
        V1VCCredentialRequest retryRequest = buildRequest("jwt-token-2");

        when(v1CredentialRequestService.buildRequest(eq(issuerDTO), eq(CREDENTIAL_CONFIG_ID),
                eq(wellKnownResponse), isNull(), isNull(), eq(false)))
                .thenReturn(firstRequest)
                .thenReturn(retryRequest);

        V1VCCredentialResponse invalidNonceResponse = V1VCCredentialResponse.builder()
                .error("invalid_nonce")
                .errorDescription("Nonce Transaction could not be found.")
                .build();

        V1VCCredentialResponse successResponse = V1VCCredentialResponse.builder()
                .credentials(List.of("retry-credential-data"))
                .build();

        when(restApiClient.postApiWithErrorResponse(eq(CREDENTIAL_ENDPOINT), eq(MediaType.APPLICATION_JSON),
                eq(firstRequest), eq(V1VCCredentialResponse.class), eq(ACCESS_TOKEN)))
                .thenReturn(invalidNonceResponse);

        when(restApiClient.postApiWithErrorResponse(eq(CREDENTIAL_ENDPOINT), eq(MediaType.APPLICATION_JSON),
                eq(retryRequest), eq(V1VCCredentialResponse.class), eq(ACCESS_TOKEN)))
                .thenReturn(successResponse);

        VCCredentialResponse result = handler.downloadCredential(issuerDTO, CREDENTIAL_CONFIG_ID,
                wellKnownResponse, tokenResponse, null, null, false);

        assertNotNull(result);
        assertEquals(FORMAT, result.getFormat());
        assertEquals("retry-credential-data", result.getCredential());
        verify(v1CredentialRequestService, times(2))
                .buildRequest(any(), anyString(), any(), any(), any(), anyBoolean());
    }

    @Test
    void shouldThrowExceptionWhenRetryAlsoReturnsInvalidNonce() throws Exception {
        V1VCCredentialRequest request = buildRequest("jwt-token");

        when(v1CredentialRequestService.buildRequest(any(), anyString(), any(), any(), any(), anyBoolean()))
                .thenReturn(request);

        V1VCCredentialResponse invalidNonceResponse = V1VCCredentialResponse.builder()
                .error("invalid_nonce")
                .errorDescription("Nonce Transaction could not be found.")
                .build();

        when(restApiClient.postApiWithErrorResponse(eq(CREDENTIAL_ENDPOINT), eq(MediaType.APPLICATION_JSON),
                eq(request), eq(V1VCCredentialResponse.class), eq(ACCESS_TOKEN)))
                .thenReturn(invalidNonceResponse);

        ExternalServiceUnavailableException exception = assertThrows(
                ExternalServiceUnavailableException.class,
                () -> handler.downloadCredential(issuerDTO, CREDENTIAL_CONFIG_ID,
                        wellKnownResponse, tokenResponse, null, null, false));

        assertTrue(exception.getMessage().contains(ISSUER_ID));
        assertTrue(exception.getMessage().contains("invalid_nonce"));
    }

    @Test
    void shouldThrowExceptionWithoutRetryWhenNoNonceEndpoint() throws Exception {
        wellKnownResponse.setNonceEndpoint(null);

        V1VCCredentialRequest request = buildRequest("jwt-token");

        when(v1CredentialRequestService.buildRequest(any(), anyString(), any(), any(), any(), anyBoolean()))
                .thenReturn(request);

        V1VCCredentialResponse invalidNonceResponse = V1VCCredentialResponse.builder()
                .error("invalid_nonce")
                .errorDescription("Nonce Transaction could not be found.")
                .build();

        when(restApiClient.postApiWithErrorResponse(eq(CREDENTIAL_ENDPOINT), eq(MediaType.APPLICATION_JSON),
                eq(request), eq(V1VCCredentialResponse.class), eq(ACCESS_TOKEN)))
                .thenReturn(invalidNonceResponse);

        assertThrows(ExternalServiceUnavailableException.class,
                () -> handler.downloadCredential(issuerDTO, CREDENTIAL_CONFIG_ID,
                        wellKnownResponse, tokenResponse, null, null, false));

        verify(v1CredentialRequestService, times(1))
                .buildRequest(any(), anyString(), any(), any(), any(), anyBoolean());
    }

    @Test
    void shouldThrowExceptionWithoutRetryWhenNonceEndpointIsBlank() throws Exception {
        wellKnownResponse.setNonceEndpoint("   ");

        V1VCCredentialRequest request = buildRequest("jwt-token");

        when(v1CredentialRequestService.buildRequest(any(), anyString(), any(), any(), any(), anyBoolean()))
                .thenReturn(request);

        V1VCCredentialResponse invalidNonceResponse = V1VCCredentialResponse.builder()
                .error("invalid_nonce")
                .errorDescription("Nonce Transaction could not be found.")
                .build();

        when(restApiClient.postApiWithErrorResponse(eq(CREDENTIAL_ENDPOINT), eq(MediaType.APPLICATION_JSON),
                eq(request), eq(V1VCCredentialResponse.class), eq(ACCESS_TOKEN)))
                .thenReturn(invalidNonceResponse);

        assertThrows(ExternalServiceUnavailableException.class,
                () -> handler.downloadCredential(issuerDTO, CREDENTIAL_CONFIG_ID,
                        wellKnownResponse, tokenResponse, null, null, false));

        verify(v1CredentialRequestService, times(1))
                .buildRequest(any(), anyString(), any(), any(), any(), anyBoolean());
    }

    @Test
    void shouldThrowInvalidCredentialResourceExceptionWhenCredentialsListIsNull() throws Exception {
        V1VCCredentialRequest request = buildRequest("jwt-token");

        when(v1CredentialRequestService.buildRequest(any(), anyString(), any(), any(), any(), anyBoolean()))
                .thenReturn(request);

        V1VCCredentialResponse mockResponse = V1VCCredentialResponse.builder()
                .credentials(null)
                .build();

        when(restApiClient.postApiWithErrorResponse(eq(CREDENTIAL_ENDPOINT), eq(MediaType.APPLICATION_JSON),
                eq(request), eq(V1VCCredentialResponse.class), eq(ACCESS_TOKEN)))
                .thenReturn(mockResponse);

        InvalidCredentialResourceException exception = assertThrows(
                InvalidCredentialResourceException.class,
                () -> handler.downloadCredential(issuerDTO, CREDENTIAL_CONFIG_ID,
                        wellKnownResponse, tokenResponse, null, null, false));

        assertTrue(exception.getMessage().contains("Credential response did not contain any credentials"));
    }

    @Test
    void shouldThrowInvalidCredentialResourceExceptionWhenCredentialsListIsEmpty() throws Exception {
        V1VCCredentialRequest request = buildRequest("jwt-token");

        when(v1CredentialRequestService.buildRequest(any(), anyString(), any(), any(), any(), anyBoolean()))
                .thenReturn(request);

        V1VCCredentialResponse mockResponse = V1VCCredentialResponse.builder()
                .credentials(List.of())
                .build();

        when(restApiClient.postApiWithErrorResponse(eq(CREDENTIAL_ENDPOINT), eq(MediaType.APPLICATION_JSON),
                eq(request), eq(V1VCCredentialResponse.class), eq(ACCESS_TOKEN)))
                .thenReturn(mockResponse);

        InvalidCredentialResourceException exception = assertThrows(
                InvalidCredentialResourceException.class,
                () -> handler.downloadCredential(issuerDTO, CREDENTIAL_CONFIG_ID,
                        wellKnownResponse, tokenResponse, null, null, false));

        assertTrue(exception.getMessage().contains("Credential response did not contain any credentials"));
    }

    @Test
    void shouldThrowExceptionWhenResponseIsNull() throws Exception {
        V1VCCredentialRequest request = buildRequest("jwt-token");

        when(v1CredentialRequestService.buildRequest(any(), anyString(), any(), any(), any(), anyBoolean()))
                .thenReturn(request);

        when(restApiClient.postApiWithErrorResponse(anyString(), any(), any(), any(), anyString()))
                .thenReturn(null);

        ExternalServiceUnavailableException exception = assertThrows(
                ExternalServiceUnavailableException.class,
                () -> handler.downloadCredential(issuerDTO, CREDENTIAL_CONFIG_ID,
                        wellKnownResponse, tokenResponse, null, null, false));

        assertTrue(exception.getMessage().contains(ISSUER_ID));
        assertTrue(exception.getMessage().contains("no response"));
        verify(v1CredentialRequestService, times(1))
                .buildRequest(any(), anyString(), any(), any(), any(), anyBoolean());
    }

    @Test
    void shouldNotRetryForNonNonceErrors() throws Exception {
        V1VCCredentialRequest request = buildRequest("jwt-token");

        when(v1CredentialRequestService.buildRequest(any(), anyString(), any(), any(), any(), anyBoolean()))
                .thenReturn(request);

        V1VCCredentialResponse errorResponse = V1VCCredentialResponse.builder()
                .error("invalid_token")
                .errorDescription("The access token is expired")
                .build();

        when(restApiClient.postApiWithErrorResponse(eq(CREDENTIAL_ENDPOINT), eq(MediaType.APPLICATION_JSON),
                eq(request), eq(V1VCCredentialResponse.class), eq(ACCESS_TOKEN)))
                .thenReturn(errorResponse);

        ExternalServiceUnavailableException exception = assertThrows(
                ExternalServiceUnavailableException.class,
                () -> handler.downloadCredential(issuerDTO, CREDENTIAL_CONFIG_ID,
                        wellKnownResponse, tokenResponse, null, null, false));

        assertTrue(exception.getMessage().contains("invalid_token"));
        verify(v1CredentialRequestService, times(1))
                .buildRequest(any(), anyString(), any(), any(), any(), anyBoolean());
        verify(restApiClient, times(1))
                .postApiWithErrorResponse(anyString(), any(), any(), any(), anyString());
    }

    @Test
    void shouldNotRetryWhenResponseIsNullAndNoNonceEndpoint() throws Exception {
        wellKnownResponse.setNonceEndpoint(null);

        V1VCCredentialRequest request = buildRequest("jwt-token");

        when(v1CredentialRequestService.buildRequest(any(), anyString(), any(), any(), any(), anyBoolean()))
                .thenReturn(request);

        when(restApiClient.postApiWithErrorResponse(anyString(), any(), any(), any(), anyString()))
                .thenReturn(null);

        assertThrows(ExternalServiceUnavailableException.class,
                () -> handler.downloadCredential(issuerDTO, CREDENTIAL_CONFIG_ID,
                        wellKnownResponse, tokenResponse, null, null, false));

        verify(v1CredentialRequestService, times(1))
                .buildRequest(any(), anyString(), any(), any(), any(), anyBoolean());
        verify(restApiClient, times(1))
                .postApiWithErrorResponse(anyString(), any(), any(), any(), anyString());
    }
}
