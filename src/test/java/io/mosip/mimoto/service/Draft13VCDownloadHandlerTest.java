package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.Draft13VCCredentialRequest;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponse;
import io.mosip.mimoto.exception.CredentialProcessingException;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.service.impl.Draft13VCDownloadHandler;
import io.mosip.mimoto.util.RestApiClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;

import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class Draft13VCDownloadHandlerTest {

    @Mock
    private CredentialRequestService credentialRequestService;

    @Mock
    private RestApiClient restApiClient;

    @InjectMocks
    private Draft13VCDownloadHandler handler;

    private IssuerDTO issuerDTO;
    private CredentialIssuerWellKnownResponse wellKnownResponse;
    private TokenResponseDTO tokenResponse;

    @BeforeEach
    void setUp() {
        issuerDTO = new IssuerDTO();
        issuerDTO.setIssuer_id("issuer-123");

        wellKnownResponse = new CredentialIssuerWellKnownResponse();
        wellKnownResponse.setCredentialEndPoint("https://example.com/credential");

        tokenResponse = new TokenResponseDTO();
        tokenResponse.setC_nonce("nonce-123");
        tokenResponse.setAccess_token("valid-access-token");
    }

    @Test
    void shouldReturnVCCredentialResponseWhenDownloadCredentialIsSuccessful() throws Exception {
        String credentialConfigurationId = "config-1";
        String walletId = "wallet-1";
        String base64Key = "base64-key";
        boolean isLoginFlow = false;

        Draft13VCCredentialRequest request = getVCCredentialRequestDTO();
        request.setFormat("jwt_vc");

        when(credentialRequestService.buildRequest(eq(issuerDTO), eq(credentialConfigurationId),
                eq(wellKnownResponse), eq(tokenResponse.getC_nonce()), eq(walletId), eq(base64Key), eq(isLoginFlow)))
                .thenReturn(request);

        VerifiableCredentialResponse mockResponse = new VerifiableCredentialResponse();
        mockResponse.setCredential("mock-credential-data");

        when(restApiClient.postApi(
                eq("https://example.com/credential"),
                eq(MediaType.APPLICATION_JSON),
                eq(request),
                eq(VerifiableCredentialResponse.class),
                eq("valid-access-token")
        )).thenReturn(mockResponse);

        VCCredentialResponse result = handler.downloadCredential(
                issuerDTO, credentialConfigurationId, wellKnownResponse, tokenResponse, walletId, base64Key, isLoginFlow);

        assertNotNull(result);
        assertEquals(request.getFormat(), result.getFormat());
        assertEquals(mockResponse.getCredential(), result.getCredential());
    }

    @Test
    void shouldThrowCredentialProcessingExceptionWhenBuildRequestFails() throws Exception {
        String credentialConfigurationId = "config-1";
        String walletId = "wallet-1";
        String base64Key = "base64-key";
        boolean isLoginFlow = false;

        when(credentialRequestService.buildRequest(any(), anyString(), any(), anyString(), anyString(), anyString(), anyBoolean()))
                .thenThrow(new RuntimeException("Build failed"));

        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () -> {
            handler.downloadCredential(issuerDTO, credentialConfigurationId, wellKnownResponse, tokenResponse, walletId, base64Key, isLoginFlow);
        });
    }

    @Test
    void shouldThrowInvalidCredentialResourceExceptionWhenRestApiReturnsNull() throws Exception {
        String credentialConfigurationId = "config-1";
        String walletId = "wallet-1";
        String base64Key = "base64-key";
        boolean isLoginFlow = false;

        Draft13VCCredentialRequest request = getVCCredentialRequestDTO();
        request.setFormat("jwt_vc");

        when(credentialRequestService.buildRequest(eq(issuerDTO), eq(credentialConfigurationId),
                eq(wellKnownResponse), eq(tokenResponse.getC_nonce()), eq(walletId), eq(base64Key), eq(isLoginFlow)))
                .thenReturn(request);

        when(restApiClient.postApi(
                eq("https://example.com/credential"),
                eq(MediaType.APPLICATION_JSON),
                eq(request),
                eq(VerifiableCredentialResponse.class),
                eq("valid-access-token")
        )).thenReturn(null);

        InvalidCredentialResourceException exception = assertThrows(
                InvalidCredentialResourceException.class,
                () -> handler.downloadCredential(issuerDTO, credentialConfigurationId, wellKnownResponse, tokenResponse, walletId, base64Key, isLoginFlow)
        );

        assertTrue(exception.getMessage().contains("VC Credential Issue API not accessible"));
    }

    @Test
    void shouldThrowExternalServiceUnavailableExceptionWhenRestApiThrowsException() throws Exception {
        String credentialConfigurationId = "config-1";
        String walletId = "wallet-1";
        String base64Key = "base64-key";
        boolean isLoginFlow = false;

        Draft13VCCredentialRequest request = getVCCredentialRequestDTO();
        request.setFormat("jwt_vc");

        when(credentialRequestService.buildRequest(eq(issuerDTO), eq(credentialConfigurationId),
                eq(wellKnownResponse), eq(tokenResponse.getC_nonce()), eq(walletId), eq(base64Key), eq(isLoginFlow)))
                .thenReturn(request);

        when(restApiClient.postApi(anyString(), any(), any(), any(), anyString()))
                .thenThrow(new RuntimeException("API down"));

        ExternalServiceUnavailableException exception = assertThrows(
                ExternalServiceUnavailableException.class,
                () -> handler.downloadCredential(issuerDTO, credentialConfigurationId, wellKnownResponse, tokenResponse, walletId, base64Key, isLoginFlow)
        );

        assertTrue(exception.getMessage().contains("Unable to download credential from issuerId"));
    }
}