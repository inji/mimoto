package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.DPoPConstants;
import io.mosip.mimoto.constant.VCSpecificationVersion;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.dpop.DPoPSession;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.DPoPChallengeException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.model.VerifiableCredential;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import static org.mockito.Mockito.mock;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.dto.mimoto.IssuerConfig;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;
import io.mosip.mimoto.exception.CredentialProcessingException;
import static io.mosip.mimoto.exception.ErrorConstants.CREDENTIAL_DOWNLOAD_EXCEPTION;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import static io.mosip.mimoto.exception.ErrorConstants.SERVER_UNAVAILABLE;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.exception.ErrorConstants.SIGNATURE_VERIFICATION_EXCEPTION;
import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
@SpringBootTest
public class CredentialServiceTest {

    @Mock
    VCDownloadHandlerFactory vcDownloadHandlerFactory;

    @Mock
    VCDownloadHandler vcDownloadHandler;

    @Mock
    CredentialVerifierService credentialVerifierService;

    @InjectMocks
    CredentialServiceImpl credentialService;

    @Mock
    CredentialPDFGeneratorService credentialUtilService;

    @Mock
    IssuersServiceImpl issuersService;

    @Mock
    IdpService idpService;

    @Mock
    DPoPSessionService dPoPSessionService;

    @Mock
    PkceSessionManager pkceSessionManager;

    @Mock
    WalletCredentialsRepository walletCredentialsRepository;

    @Mock
    DataProtectionService dataProtectionService;

    @Mock
    ObjectMapper objectMapper;

    TokenResponseDTO expectedTokenResponse;
    String tokenEndpoint, issuerId;
    IssuerDTO issuerDTO;
    HttpEntity<MultiValueMap<String, String>> mockRequest;
    CredentialIssuerConfiguration issuerConfig;
    CredentialIssuerWellKnownResponse wellKnownResponse;

    @Before
    public void setUp() throws Exception {
        issuerId = "issuer1";
        issuerDTO = getIssuerConfigDTO(issuerId);
        issuerConfig = getCredentialIssuerConfigurationResponseDto(issuerId, "CredentialType1", List.of());

        wellKnownResponse = getCredentialIssuerWellKnownResponseDto(issuerId,
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
        wellKnownResponse.setVersion(VCSpecificationVersion.DRAFT_13);

        Mockito.when(issuersService.getIssuerDetails(issuerId)).thenReturn(issuerDTO);
        Mockito.when(issuersService.getIssuerWellKnownResponse(issuerDTO.getCredential_issuer_host())).thenReturn(wellKnownResponse);

        tokenEndpoint = issuerConfig.getAuthorizationServerWellKnownResponse().getTokenEndpoint();
        mockRequest = new HttpEntity<>(new LinkedMultiValueMap<>(Map.of(
                "grant_type", List.of("client_credentials"),
                "client_id", List.of("test-client")
        )));
        expectedTokenResponse = getTokenResponseDTO();
    }

    @Test
    public void shouldParseHtmlStringToDocument() {
        String htmlContent = "<html><body><h1>$message</h1></body></html>";
        Map<String, Object> data = new HashMap<>();
        data.put("message", "PDF");
        VelocityContext velocityContext = new VelocityContext();
        StringWriter writer = new StringWriter();
        velocityContext.put("message", data.get("message"));
        Velocity.evaluate(velocityContext, writer, "Credential Template", htmlContent);
        String mergedHtml = writer.toString();
        assertTrue(mergedHtml.contains("PDF"));
    }

    @Test
    public void shouldThrowExceptionIfDownloadedVCSignatureVerificationFailed() throws Exception {
        when(vcDownloadHandlerFactory.getHandler(VCSpecificationVersion.DRAFT_13)).thenReturn(vcDownloadHandler);
        when(vcDownloadHandler.downloadCredential(any(IssuerDTO.class), any(String.class),
                any(CredentialIssuerWellKnownResponse.class), any(TokenResponseDTO.class),
                any(), any(), eq(false), any())).thenReturn(getVCCredentialResponseDTO("CredentialType1"));
        when(credentialVerifierService.verify(any(VCCredentialResponse.class))).thenReturn(false);
        VCVerificationException actualException = assertThrows(VCVerificationException.class, this::downloadPdf);

        assertEquals("signature_verification_failed --> Error while doing signature verification", actualException.getMessage());
    }

    @Test
    public void shouldReturnDownloadedVCAsPDFIfSignatureVerificationIsSuccessful() throws Exception {
        when(vcDownloadHandlerFactory.getHandler(VCSpecificationVersion.DRAFT_13)).thenReturn(vcDownloadHandler);
        when(vcDownloadHandler.downloadCredential(any(IssuerDTO.class), any(String.class),
                any(CredentialIssuerWellKnownResponse.class), any(TokenResponseDTO.class),
                any(), any(), eq(false), any())).thenReturn(getVCCredentialResponseDTO("CredentialType1"));
        when(credentialVerifierService.verify(any(VCCredentialResponse.class))).thenReturn(true);
        issuerDTO.setQr_code_type(QRCodeType.None);

        ByteArrayInputStream expectedPDFByteArray = generatePdfFromHTML();
        Mockito.when(credentialUtilService.generatePdfForVerifiableCredential(
                eq("CredentialType1"),
                any(VCCredentialResponse.class),
                eq(issuerDTO),
                eq(wellKnownResponse.getCredentialConfigurationsSupported().get("CredentialType1")),
                eq(""),
                eq("once"),
                eq("en")
        )).thenReturn(expectedPDFByteArray);

        ByteArrayInputStream actualPDFByteArray = downloadPdf();

        assertEquals(expectedPDFByteArray, actualPDFByteArray);
    }

    @Test
    public void shouldRetryCredentialProofWhenIssuerRequiresDPoPNonce() throws Exception {
        when(vcDownloadHandlerFactory.getHandler(VCSpecificationVersion.DRAFT_13)).thenReturn(vcDownloadHandler);
        HttpHeaders challengeHeaders = new HttpHeaders();
        challengeHeaders.set(DPoPConstants.DPOP_NONCE_HEADER, "issuer-nonce");
        when(vcDownloadHandler.downloadCredential(any(IssuerDTO.class), any(String.class),
                any(CredentialIssuerWellKnownResponse.class), any(TokenResponseDTO.class),
                any(), any(), eq(false), any()))
                .thenThrow(new DPoPChallengeException(HttpStatus.UNAUTHORIZED, challengeHeaders, "{}"))
                .thenReturn(getVCCredentialResponseDTO("CredentialType1"));
        when(credentialVerifierService.verify(any(VCCredentialResponse.class))).thenReturn(true);
        issuerDTO.setQr_code_type(QRCodeType.None);
        ByteArrayInputStream expectedPDFByteArray = generatePdfFromHTML();
        Mockito.when(credentialUtilService.generatePdfForVerifiableCredential(
                eq("CredentialType1"),
                any(VCCredentialResponse.class),
                eq(issuerDTO),
                eq(wellKnownResponse.getCredentialConfigurationsSupported().get("CredentialType1")),
                eq(""),
                eq("once"),
                eq("en")
        )).thenReturn(expectedPDFByteArray);
        stubTokenExchange(expectedTokenResponse);
        when(dPoPSessionService.retryCredentialProof(any(), eq("oauth-state"), any(), eq("issuer-nonce"), any()))
                .thenReturn("retry-proof");

        ByteArrayInputStream actualPDFByteArray = downloadPdf();

        assertEquals(expectedPDFByteArray, actualPDFByteArray);
        verify(dPoPSessionService).retryCredentialProof(any(), eq("oauth-state"), any(), eq("issuer-nonce"), any());
    }

    @Test
    public void shouldRetryWalletCredentialProofWhenIssuerRequiresDPoPNonce() throws Exception {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String localIssuerId = "issuer1";
        String locale = "en";
        IssuerConfig localIssuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(localIssuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");
        mockWellKnownResponse.setVersion(VCSpecificationVersion.DRAFT_13);
        VerifiableCredential savedCredential = new VerifiableCredential();
        savedCredential.setId("credential-id-123");
        HttpHeaders challengeHeaders = new HttpHeaders();
        challengeHeaders.set(DPoPConstants.DPOP_NONCE_HEADER, "wallet-issuer-nonce");

        when(localIssuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(localIssuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);
        when(issuersService.getIssuerConfig(localIssuerId, credentialConfigurationId)).thenReturn(localIssuerConfig);
        when(vcDownloadHandlerFactory.getHandler(VCSpecificationVersion.DRAFT_13)).thenReturn(vcDownloadHandler);
        when(vcDownloadHandler.downloadCredential(any(), eq(credentialConfigurationId), any(), any(), eq(walletId), eq(base64Key), eq(true), any()))
                .thenThrow(new DPoPChallengeException(HttpStatus.UNAUTHORIZED, challengeHeaders, "{}"))
                .thenReturn(getVCCredentialResponseDTO(credentialConfigurationId));
        when(credentialVerifierService.verify(any(VCCredentialResponse.class))).thenReturn(true);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(dataProtectionService.encryptCredential(any(), eq(base64Key))).thenReturn("encrypted-credential");
        when(walletCredentialsRepository.save(any(VerifiableCredential.class))).thenReturn(savedCredential);
        when(dPoPSessionService.retryCredentialProof(any(), eq("oauth-state"), any(), eq("wallet-issuer-nonce"), any()))
                .thenReturn("retry-proof");

        VerifiableCredentialResponseDTO result = downloadAndStore(
                tokenResponse, credentialConfigurationId, walletId, base64Key, localIssuerId, locale);

        assertNotNull(result);
        assertEquals("credential-id-123", result.getCredentialId());
        verify(dPoPSessionService).retryCredentialProof(any(), eq("oauth-state"), any(), eq("wallet-issuer-nonce"), any());
    }

    @Test
    public void shouldThrowInvalidRequestExceptionWhenDPoPStateIsBlank() {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                credentialService.downloadCredentialAsPDF(
                        issuerId, "CredentialType1", "once", "en", "auth-code", " ", new MockHttpSession()));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("DPoP state is required"));
    }

    @Test
    public void shouldThrowInvalidRequestExceptionWhenDPoPSessionIsMissing() {
        when(dPoPSessionService.find(any(), eq("oauth-state"))).thenReturn(null);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                credentialService.downloadCredentialAsPDF(
                        issuerId, "CredentialType1", "once", "en", "auth-code", "oauth-state", new MockHttpSession()));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("DPoP session not found or token is not bound"));
    }

    @Test
    public void shouldDownloadCredentialAndStoreInDBSuccessfully() throws Exception {
        // Setup test data
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String localIssuerId = "issuer1";
        String locale = "en";

        // Mock dependencies
        IssuerConfig localIssuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(localIssuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");
        mockWellKnownResponse.setVersion(VCSpecificationVersion.DRAFT_13);

        VerifiableCredential savedCredential = new VerifiableCredential();
        savedCredential.setId("credential-id-123");

        // Setup issuer config mocks
        when(localIssuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(localIssuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);

        // Mock service calls
        when(issuersService.getIssuerConfig(localIssuerId, credentialConfigurationId)).thenReturn(localIssuerConfig);
        when(vcDownloadHandlerFactory.getHandler(VCSpecificationVersion.DRAFT_13)).thenReturn(vcDownloadHandler);
        when(vcDownloadHandler.downloadCredential(any(), eq(credentialConfigurationId), any(), any(), eq(walletId), eq(base64Key), eq(true), any()))
                .thenReturn(getVCCredentialResponseDTO(credentialConfigurationId));
        when(credentialVerifierService.verify(any(VCCredentialResponse.class))).thenReturn(true);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(dataProtectionService.encryptCredential(any(), eq(base64Key))).thenReturn("encrypted-credential");
        when(walletCredentialsRepository.save(any(VerifiableCredential.class))).thenReturn(savedCredential);

        // Execute
        VerifiableCredentialResponseDTO result = downloadAndStore(
                tokenResponse, credentialConfigurationId, walletId, base64Key, localIssuerId, locale);

        // Verify
        assertNotNull(result);
        assertEquals("credential-id-123", result.getCredentialId());
    }

    @Test
    public void shouldThrowVCVerificationExceptionWhenVerificationFails() throws Exception {
        // Setup test data
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String localIssuerId = "issuer1";
        String locale = "en";

        // Mock dependencies
        IssuerConfig localIssuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(localIssuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");
        mockWellKnownResponse.setVersion(VCSpecificationVersion.DRAFT_13);

        // Setup issuer config mocks
        when(localIssuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(localIssuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);

        // Mock service calls
        when(issuersService.getIssuerConfig(localIssuerId, credentialConfigurationId)).thenReturn(localIssuerConfig);
        when(vcDownloadHandlerFactory.getHandler(VCSpecificationVersion.DRAFT_13)).thenReturn(vcDownloadHandler);
        when(vcDownloadHandler.downloadCredential(any(), any(), any(), any(), any(), any(), eq(true), any()))
                .thenReturn(getVCCredentialResponseDTO(credentialConfigurationId));
        when(credentialVerifierService.verify(any())).thenReturn(false);

        // Execute and verify exception
        VCVerificationException exception = assertThrows(VCVerificationException.class, () ->
                downloadAndStore(tokenResponse, credentialConfigurationId, walletId, base64Key, localIssuerId, locale));

        assertEquals(SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(), exception.getErrorCode());
    }

    @Test
    public void shouldThrowInvalidRequestExceptionForNullTokenResponse() throws Exception {
        when(dPoPSessionService.find(any(), eq("oauth-state")))
                .thenReturn(DPoPSession.builder().state("oauth-state").build());
        when(pkceSessionManager.authorizationCodeParams(any(), eq("oauth-state"), any(), any()))
                .thenReturn(Map.of("code", "auth-code"));
        when(idpService.exchangeAndBindToken(any(), any())).thenReturn(null);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(
                        issuerId, "CredentialType1", "wallet123", "testKey123", "en",
                        "auth-code", "oauth-state", new MockHttpSession()));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("DPoP session not found or token is not bound"));
    }

    @Test
    public void shouldThrowInvalidRequestExceptionForBlankAccessToken() throws Exception {
        TokenResponseDTO tokenResponse = new TokenResponseDTO();
        tokenResponse.setAccess_token("");

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                downloadAndStore(tokenResponse, "CredentialType1", "wallet123", "testKey123", "issuer1", "en"));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Token response or access token cannot be null"));
    }

    @Test
    public void shouldThrowInvalidRequestExceptionForBlankCredentialConfigurationId() throws Exception {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                downloadAndStore(getTokenResponseDTO(), "", "wallet123", "testKey123", "issuer1", "en"));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Credential configuration id cannot be null or blank"));
    }

    @Test
    public void shouldThrowInvalidRequestExceptionForBlankWalletId() throws Exception {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                downloadAndStore(getTokenResponseDTO(), "CredentialType1", "", "testKey123", "issuer1", "en"));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Wallet ID cannot be null or blank"));
    }

    @Test
    public void shouldThrowInvalidRequestExceptionForBlankBase64Key() throws Exception {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                downloadAndStore(getTokenResponseDTO(), "CredentialType1", "wallet123", "", "issuer1", "en"));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Wallet key cannot be null or blank"));
    }

    @Test
    public void shouldThrowInvalidRequestExceptionForBlankIssuerId() throws Exception {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                downloadAndStore(getTokenResponseDTO(), "CredentialType1", "wallet123", "testKey123", "", "en"));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Issuer ID cannot be null or blank"));
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionWhenFetchIssuerConfigFails() throws Exception {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String localIssuerId = "issuer1";
        String locale = "en";

        // Mock issuersService to throw exception
        when(issuersService.getIssuerConfig(localIssuerId, credentialConfigurationId))
                .thenThrow(new RuntimeException("Issuer service unavailable"));

        // Execute and verify exception
        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                downloadAndStore(tokenResponse, credentialConfigurationId, walletId, base64Key, localIssuerId, locale));

        assertEquals(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Unable to fetch issuer configuration"));
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionWhenBuildCredentialRequestFails() throws Exception {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String localIssuerId = "issuer1";
        String locale = "en";

        // Mock dependencies for success until buildRequest
        IssuerConfig localIssuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(localIssuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setVersion(VCSpecificationVersion.DRAFT_13);

        when(localIssuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(localIssuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);
        when(issuersService.getIssuerConfig(localIssuerId, credentialConfigurationId)).thenReturn(localIssuerConfig);
        when(vcDownloadHandlerFactory.getHandler(VCSpecificationVersion.DRAFT_13)).thenReturn(vcDownloadHandler);

        // Mock vcDownloadHandler to throw exception (simulating build credential request failure)
        when(vcDownloadHandler.downloadCredential(any(), eq(credentialConfigurationId), any(), any(), eq(walletId), eq(base64Key), eq(true), any()))
                .thenThrow(new CredentialProcessingException(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), "Unable to generate credential request"));

        // Execute and verify exception
        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                downloadAndStore(tokenResponse, credentialConfigurationId, walletId, base64Key, localIssuerId, locale));

        assertEquals(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Unable to generate credential request"));
    }

    @Test
    public void shouldThrowExternalServiceUnavailableExceptionWhenDownloadCredentialFromIssuerFails() throws Exception {
        TokenResponseDTO tokenResponse = TestUtilities.getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String localIssuerId = "issuer1";
        String locale = "en";

        // Mock dependencies for success until downloadCredential
        IssuerConfig localIssuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = TestUtilities.getIssuerConfigDTO(localIssuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");
        mockWellKnownResponse.setVersion(VCSpecificationVersion.DRAFT_13);

        when(localIssuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(localIssuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);
        when(issuersService.getIssuerConfig(localIssuerId, credentialConfigurationId)).thenReturn(localIssuerConfig);
        when(vcDownloadHandlerFactory.getHandler(VCSpecificationVersion.DRAFT_13)).thenReturn(vcDownloadHandler);

        // Mock vcDownloadHandler to throw exception during credential download
        when(vcDownloadHandler.downloadCredential(any(), any(), any(), any(), any(), any(), eq(true), any()))
                .thenThrow(new ExternalServiceUnavailableException(SERVER_UNAVAILABLE.getErrorCode(), SERVER_UNAVAILABLE.getErrorMessage()));

        // Execute and verify exception
        ExternalServiceUnavailableException exception = assertThrows(ExternalServiceUnavailableException.class, () ->
                downloadAndStore(tokenResponse, credentialConfigurationId, walletId, base64Key, localIssuerId, locale));

        assertEquals(SERVER_UNAVAILABLE.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains(SERVER_UNAVAILABLE.getErrorMessage()));
    }

    @Test
    public void shouldThrowVCVerificationExceptionWhenCredentialVerifierServiceThrowsException() throws Exception {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String localIssuerId = "issuer1";
        String locale = "en";

        // Mock dependencies for success until verify
        IssuerConfig localIssuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(localIssuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");
        mockWellKnownResponse.setVersion(VCSpecificationVersion.DRAFT_13);

        when(localIssuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(localIssuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);
        when(issuersService.getIssuerConfig(localIssuerId, credentialConfigurationId)).thenReturn(localIssuerConfig);
        when(vcDownloadHandlerFactory.getHandler(VCSpecificationVersion.DRAFT_13)).thenReturn(vcDownloadHandler);
        when(vcDownloadHandler.downloadCredential(any(), any(), any(), any(), any(), any(), eq(true), any()))
                .thenReturn(getVCCredentialResponseDTO(credentialConfigurationId));

        // Mock credentialVerifierService to throw exception
        when(credentialVerifierService.verify(any(VCCredentialResponse.class)))
                .thenThrow(new JsonProcessingException("JSON processing failed") {});

        // Execute and verify exception
        VCVerificationException exception = assertThrows(VCVerificationException.class, () ->
                downloadAndStore(tokenResponse, credentialConfigurationId, walletId, base64Key, localIssuerId, locale));

        assertEquals(SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Credential verification failed"));
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionWhenSerializationFails() throws Exception {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String localIssuerId = "issuer1";
        String locale = "en";

        // Mock dependencies for success until serialization
        IssuerConfig localIssuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(localIssuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");
        mockWellKnownResponse.setVersion(VCSpecificationVersion.DRAFT_13);

        when(localIssuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(localIssuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);
        when(issuersService.getIssuerConfig(localIssuerId, credentialConfigurationId)).thenReturn(localIssuerConfig);
        when(vcDownloadHandlerFactory.getHandler(VCSpecificationVersion.DRAFT_13)).thenReturn(vcDownloadHandler);
        when(vcDownloadHandler.downloadCredential(any(), any(), any(), any(), any(), any(), eq(true), any()))
                .thenReturn(getVCCredentialResponseDTO(credentialConfigurationId));
        when(credentialVerifierService.verify(any(VCCredentialResponse.class))).thenReturn(true);

        // Mock objectMapper to throw JsonProcessingException
        when(objectMapper.writeValueAsString(any()))
                .thenThrow(new JsonProcessingException("Serialization failed") {});

        // Execute and verify exception
        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                downloadAndStore(tokenResponse, credentialConfigurationId, walletId, base64Key, localIssuerId, locale));

        assertEquals(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Unable to serialize credential response"));
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionWhenEncryptionFails() throws Exception {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String localIssuerId = "issuer1";
        String locale = "en";

        // Mock dependencies for success until encryption
        IssuerConfig localIssuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(localIssuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");
        mockWellKnownResponse.setVersion(VCSpecificationVersion.DRAFT_13);

        when(localIssuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(localIssuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);
        when(issuersService.getIssuerConfig(localIssuerId, credentialConfigurationId)).thenReturn(localIssuerConfig);
        when(vcDownloadHandlerFactory.getHandler(VCSpecificationVersion.DRAFT_13)).thenReturn(vcDownloadHandler);
        when(vcDownloadHandler.downloadCredential(any(), any(), any(), any(), any(), any(), eq(true), any()))
                .thenReturn(getVCCredentialResponseDTO(credentialConfigurationId));
        when(credentialVerifierService.verify(any(VCCredentialResponse.class))).thenReturn(true);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");

        // Mock dataProtectionService to throw exception
        when(dataProtectionService.encryptCredential(any(), eq(base64Key)))
                .thenThrow(new RuntimeException("Encryption failed"));

        // Execute and verify exception
        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                downloadAndStore(tokenResponse, credentialConfigurationId, walletId, base64Key, localIssuerId, locale));

        assertEquals(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Unable to encrypt credential data"));
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionWhenSaveCredentialFails() throws Exception {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String localIssuerId = "issuer1";
        String locale = "en";

        // Mock dependencies for success until save
        IssuerConfig localIssuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(localIssuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");
        mockWellKnownResponse.setVersion(VCSpecificationVersion.DRAFT_13);

        when(localIssuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(localIssuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);
        when(issuersService.getIssuerConfig(localIssuerId, credentialConfigurationId)).thenReturn(localIssuerConfig);
        when(vcDownloadHandlerFactory.getHandler(VCSpecificationVersion.DRAFT_13)).thenReturn(vcDownloadHandler);
        when(vcDownloadHandler.downloadCredential(any(), any(), any(), any(), any(), any(), eq(true), any()))
                .thenReturn(getVCCredentialResponseDTO(credentialConfigurationId));
        when(credentialVerifierService.verify(any(VCCredentialResponse.class))).thenReturn(true);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(dataProtectionService.encryptCredential(any(), eq(base64Key))).thenReturn("encrypted-credential");

        // Mock walletCredentialsRepository to throw exception
        when(walletCredentialsRepository.save(any(VerifiableCredential.class)))
                .thenThrow(new RuntimeException("Database connection failed"));

        // Execute and verify exception
        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                downloadAndStore(tokenResponse, credentialConfigurationId, walletId, base64Key, localIssuerId, locale));

        assertEquals(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Unable to save credential to database"));
    }

    private ByteArrayInputStream downloadPdf() throws Exception {
        stubTokenExchange(expectedTokenResponse);
        return credentialService.downloadCredentialAsPDF(
                issuerId, "CredentialType1", "once", "en", "auth-code", "oauth-state", new MockHttpSession());
    }

    private VerifiableCredentialResponseDTO downloadAndStore(TokenResponseDTO tokenResponse,
                                                             String credentialConfigurationId, String walletId,
                                                             String base64Key, String issuerId, String locale)
            throws Exception {
        stubTokenExchange(tokenResponse);
        return credentialService.downloadCredentialAndStoreInDB(
                issuerId, credentialConfigurationId, walletId, base64Key, locale,
                "auth-code", "oauth-state", new MockHttpSession());
    }

    private void stubTokenExchange(TokenResponseDTO tokenResponse) throws Exception {
        when(dPoPSessionService.find(any(), eq("oauth-state")))
                .thenReturn(DPoPSession.builder().state("oauth-state").build());
        when(pkceSessionManager.authorizationCodeParams(any(), eq("oauth-state"), any(), any()))
                .thenReturn(Map.of("code", "auth-code"));
        when(idpService.exchangeAndBindToken(any(), any())).thenReturn(tokenResponse);
        when(dPoPSessionService.credentialProof(any(), eq("oauth-state"), any(), any())).thenReturn("server-dPoP");
    }
}
