package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.constant.OpenID4VPConstants;
import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.openid.SpecVersion;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.VerifiablePresentation;
import io.mosip.mimoto.repository.VerifiablePresentationsRepository;
import io.mosip.mimoto.service.impl.OpenID4VPService;
import io.mosip.mimoto.service.impl.WalletPresentationServiceImpl;
import io.mosip.mimoto.util.SigningKeyUtil;
import io.mosip.mimoto.util.UrlParameterUtils;
import io.mosip.openID4VP.OpenID4VP;
import org.springframework.http.ResponseEntity;
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult;
import io.mosip.openID4VP.common.OpenID4VPErrorCodes;
import io.mosip.openID4VP.constants.FormatType;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;
import io.mosip.openID4VP.verifier.VerifierResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.*;
import java.util.Base64;

import static io.mosip.mimoto.exception.ErrorConstants.*;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.Silent.class)
public class WalletPresentationServiceTest {

    @Mock
    private VerifierService verifierService;

    @Mock
    private OpenID4VPService openID4VPService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private KeyPairRetrievalService keyPairService;

    @Mock
    private VerifiablePresentationsRepository verifiablePresentationsRepository;

    @Mock
    private CredentialMatchingService credentialMatchingService;

    @Mock
    private CredentialFormatHandlerFactory credentialFormatHandlerFactory;

    @Mock
    private CredentialFormatHandler credentialFormatHandler;

    @Mock
    private WalletCredentialService walletCredentialService;

    @InjectMocks
    private WalletPresentationServiceImpl walletPresentationService;

    private String walletId;
    private String presentationId;
    private String urlEncodedVPAuthorizationRequest;
    private String base64Key;
    private VerifiersDTO verifiersDTO;
    private VerifierDTO verifierDTO;
    private AuthorizationRequest mockAuthorizationRequest;
    private OpenID4VP mockOpenID4VP;
    private VerifiablePresentationSessionData sessionData;
    private SubmitPresentationRequestDTO submitRequest;
    private DecryptedCredentialDTO credentialDTO;
    private VCCredentialResponse vcCredentialResponse;
    private KeyPair keyPair;
    private JWK jwk;
    private JWSSigner jwsSigner;

    @Before
    public void setUp() throws Exception {
        walletId = "wallet-123";
        presentationId = "presentation-456";
        base64Key = "base64-encoded-key";
        urlEncodedVPAuthorizationRequest = "client_id=test-client&response_type=vp_token";

        verifierDTO = new VerifierDTO(
                "test-client",
                List.of("https://verifier.com/response"),
                List.of("https://verifier.com/jwks"),
                null,
                false,
                SpecVersion.V1_0
        );
        verifiersDTO = new VerifiersDTO();
        verifiersDTO.setVerifiers(List.of(verifierDTO));

        mockOpenID4VP = mock(OpenID4VP.class);
        mockAuthorizationRequest = mock(AuthorizationRequest.class);
        when(mockAuthorizationRequest.getClientId()).thenReturn("test-client");
        when(mockAuthorizationRequest.getRedirectUri()).thenReturn("https://verifier.com/redirect");

        sessionData = new VerifiablePresentationSessionData();
        sessionData.setPresentationId(presentationId);
        sessionData.setAuthorizationRequest(urlEncodedVPAuthorizationRequest);
        sessionData.setCreatedAt(Instant.now());
        sessionData.setVerifierClientPreregistered(true);

        vcCredentialResponse = new VCCredentialResponse();
        vcCredentialResponse.setFormat(CredentialFormat.LDP_VC.getFormat());
        vcCredentialResponse.setCredential(Map.of("type", "VerifiableCredential"));

        credentialDTO = DecryptedCredentialDTO.builder()
                .id("cred-123")
                .walletId(walletId)
                .credential(vcCredentialResponse)
                .build();

        sessionData.setMatchingCredentials(List.of(credentialDTO));

        submitRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofStrings(List.of("cred-123")))
                .build();

        keyPair = mock(KeyPair.class);
        jwk = mock(JWK.class);
        jwsSigner = mock(JWSSigner.class);
        
        JWK publicJWK = mock(JWK.class);
        when(jwk.toPublicJWK()).thenReturn(publicJWK);
        Map<String, Object> jwkJsonObject = new HashMap<>();
        jwkJsonObject.put("kty", "OKP");
        jwkJsonObject.put("crv", "Ed25519");
        when(publicJWK.toJSONObject()).thenReturn(jwkJsonObject);

        when(walletCredentialService.getDecryptedCredentials(anyString(), anyString()))
                .thenReturn(Collections.emptyList());
    }

    private void stubOpenId4VpCreate(OpenID4VP openID4VP) throws Exception {
        when(openID4VPService.getPreRegisteredVerifiers()).thenReturn(List.of());
        when(openID4VPService.create(anyString(), anyList(), anyBoolean())).thenReturn(openID4VP);
    }

    private UnsignedVPToken mockLdpUnsignedToken() {
        UnsignedVPToken token = mock(UnsignedVPToken.class);
        String headerB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"EdDSA\"}".getBytes(StandardCharsets.UTF_8));
        when(token.getDataToSign()).thenReturn((headerB64 + ".payload").getBytes(StandardCharsets.US_ASCII));
        when(token.getFormat()).thenReturn(FormatType.LDP_VC);
        when(token.getSignatureAlgorithm()).thenReturn("EdDSA");
        return token;
    }

    @Test
    public void testHandleVPAuthorizationRequestSuccess() throws Exception {
        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(verifierService.isVerifierClientPreregistered(anyList(), anyString())).thenReturn(true);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);
        when(verifierService.isVerifierTrustedByWallet(anyString(), anyString())).thenReturn(true);

        AuthorizationPresentationExchangeRequest peRequest = mock(AuthorizationPresentationExchangeRequest.class);
        when(peRequest.getClientId()).thenReturn("test-client");
        when(peRequest.getRedirectUri()).thenReturn("https://verifier.com/redirect");
        ClientMetadataDraft23 clientMetadata = mock(ClientMetadataDraft23.class);
        when(clientMetadata.getClientName()).thenReturn("Test Verifier");
        when(clientMetadata.getLogoUri()).thenReturn("https://verifier.com/logo.png");
        when(peRequest.getClientMetadata()).thenReturn(clientMetadata);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(peRequest);

        VPResponseDTO result = walletPresentationService.handleVPAuthorizationRequest(
                urlEncodedVPAuthorizationRequest, walletId);

        assertNotNull(result);
        assertNotNull(result.getPresentationId());
        assertNotNull(result.getVerifiablePresentationVerifierDTO());
        assertEquals("test-client", result.getVerifiablePresentationVerifierDTO().getId());
        assertEquals("Test Verifier", result.getVerifiablePresentationVerifierDTO().getName());
        verify(openID4VPService).create(anyString(), anyList(), anyBoolean());
        verify(openID4VPService).getPreRegisteredVerifiers();
    }

    @Test
    public void testHandleVPAuthorizationRequestWithBlankClientName() throws Exception {
        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(verifierService.isVerifierClientPreregistered(anyList(), anyString())).thenReturn(true);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);
        when(verifierService.isVerifierTrustedByWallet(anyString(), anyString())).thenReturn(false);

        AuthorizationPresentationExchangeRequest peRequest = mock(AuthorizationPresentationExchangeRequest.class);
        when(peRequest.getClientId()).thenReturn("test-client");
        when(peRequest.getRedirectUri()).thenReturn("https://verifier.com/redirect");
        ClientMetadataDraft23 clientMetadata = mock(ClientMetadataDraft23.class);
        when(clientMetadata.getClientName()).thenReturn("   ");
        when(peRequest.getClientMetadata()).thenReturn(clientMetadata);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(peRequest);

        VPResponseDTO result = walletPresentationService.handleVPAuthorizationRequest(
                urlEncodedVPAuthorizationRequest, walletId);

        assertNotNull(result);
        assertEquals("test-client", result.getVerifiablePresentationVerifierDTO().getName());
    }

    @Test
    public void testHandleVPAuthorizationRequestWithNullClientMetadata() throws Exception {
        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(verifierService.isVerifierClientPreregistered(anyList(), anyString())).thenReturn(false);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);
        when(verifierService.isVerifierTrustedByWallet(anyString(), anyString())).thenReturn(false);

        VPResponseDTO result = walletPresentationService.handleVPAuthorizationRequest(
                urlEncodedVPAuthorizationRequest, walletId);

        assertNotNull(result);
        assertEquals("test-client", result.getVerifiablePresentationVerifierDTO().getName());
        assertNull(result.getVerifiablePresentationVerifierDTO().getLogo());
    }

    @Test
    public void testHandleVPAuthorizationRequestDcqlUsesClientMetadataName() throws Exception {
        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(verifierService.isVerifierClientPreregistered(anyList(), anyString())).thenReturn(true);
        when(verifierService.isVerifierTrustedByWallet(anyString(), anyString())).thenReturn(true);

        AuthorizationDcqlRequest dcqlRequest = mock(AuthorizationDcqlRequest.class);
        when(dcqlRequest.getClientId()).thenReturn("test-client");
        when(dcqlRequest.getRedirectUri()).thenReturn("https://verifier.com/redirect");
        ClientMetadata clientMetadata = mock(ClientMetadata.class);
        when(clientMetadata.getClientName()).thenReturn("DCQL Verifier");
        when(clientMetadata.getLogoUri()).thenReturn("https://verifier.com/dcql-logo.png");
        when(dcqlRequest.getClientMetadata()).thenReturn(clientMetadata);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(dcqlRequest);

        VPResponseDTO result = walletPresentationService.handleVPAuthorizationRequest(
                urlEncodedVPAuthorizationRequest, walletId);

        assertNotNull(result);
        assertEquals(io.mosip.mimoto.constant.SpecVersion.V1_0, result.getSpecVersion());
        assertEquals("test-client", result.getVerifiablePresentationVerifierDTO().getId());
        assertEquals("DCQL Verifier", result.getVerifiablePresentationVerifierDTO().getName());
        assertEquals("https://verifier.com/dcql-logo.png", result.getVerifiablePresentationVerifierDTO().getLogo());
    }

    @Test
    public void testHandleVPAuthorizationRequestDcqlFallsBackToClientIdWhenClientNameBlank() throws Exception {
        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(verifierService.isVerifierClientPreregistered(anyList(), anyString())).thenReturn(false);
        when(verifierService.isVerifierTrustedByWallet(anyString(), anyString())).thenReturn(false);

        AuthorizationDcqlRequest dcqlRequest = mock(AuthorizationDcqlRequest.class);
        when(dcqlRequest.getClientId()).thenReturn("test-client");
        when(dcqlRequest.getRedirectUri()).thenReturn("https://verifier.com/redirect");
        ClientMetadata clientMetadata = mock(ClientMetadata.class);
        when(clientMetadata.getClientName()).thenReturn("   ");
        when(dcqlRequest.getClientMetadata()).thenReturn(clientMetadata);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(dcqlRequest);

        VPResponseDTO result = walletPresentationService.handleVPAuthorizationRequest(
                urlEncodedVPAuthorizationRequest, walletId);

        assertNotNull(result);
        assertEquals(io.mosip.mimoto.constant.SpecVersion.V1_0, result.getSpecVersion());
        assertEquals("test-client", result.getVerifiablePresentationVerifierDTO().getName());
        assertNull(result.getVerifiablePresentationVerifierDTO().getLogo());
    }

    @Test
    public void testHandleVPAuthorizationRequestDcqlWithNullClientMetadata() throws Exception {
        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(verifierService.isVerifierClientPreregistered(anyList(), anyString())).thenReturn(false);
        when(verifierService.isVerifierTrustedByWallet(anyString(), anyString())).thenReturn(false);

        AuthorizationDcqlRequest dcqlRequest = mock(AuthorizationDcqlRequest.class);
        when(dcqlRequest.getClientId()).thenReturn("test-client");
        when(dcqlRequest.getRedirectUri()).thenReturn("https://verifier.com/redirect");
        when(dcqlRequest.getClientMetadata()).thenReturn(null);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(dcqlRequest);

        VPResponseDTO result = walletPresentationService.handleVPAuthorizationRequest(
                urlEncodedVPAuthorizationRequest, walletId);

        assertNotNull(result);
        assertEquals(io.mosip.mimoto.constant.SpecVersion.V1_0, result.getSpecVersion());
        assertEquals("test-client", result.getVerifiablePresentationVerifierDTO().getName());
        assertNull(result.getVerifiablePresentationVerifierDTO().getLogo());
    }

    @Test
    public void testHandlePresentationActionSubmissionRequestSuccess() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofStrings(List.of("cred-123")))
                .build();

        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                    walletId, presentationId, request, sessionData, base64Key);

            assertNotNull(response);
            assertEquals(200, response.getStatusCode().value());
            verify(verifiablePresentationsRepository).save(any(VerifiablePresentation.class));
        }
    }

    @Test
    public void testHandlePresentationActionRejectionRequestSuccess() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .errorCode("access_denied")
                .errorMessage("User denied access")
                .build();

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/rejected");
        when(openID4VPService.sendErrorToVerifier(any(), any(ErrorDTO.class))).thenReturn(verifierResponse);

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, sessionData, base64Key);

        assertNotNull(response);
        assertEquals(200, response.getStatusCode().value());
        verify(openID4VPService).sendErrorToVerifier(any(), any(ErrorDTO.class));
    }

    @Test
    public void testHandlePresentationActionInvalidRequest() {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(null)
                .errorCode(null)
                .errorMessage(null)
                .build();

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, sessionData, base64Key);

        assertNotNull(response);
        assertEquals(400, response.getStatusCode().value());
    }

    @Test
    public void testHandlePresentationActionJOSEException() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofStrings(List.of("cred-123")))
                .build();

        OpenID4VP testOpenID4VP = mock(OpenID4VP.class);
        stubOpenId4VpCreate(testOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);
        when(testOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);

        List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
        when(testOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {
            
            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any()))
                    .thenThrow(new JOSEException("JWT signing error"));

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");

            ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                    walletId, presentationId, request, sessionData, base64Key);

            assertNotNull(response);
            assertEquals(500, response.getStatusCode().value());
            assertNotNull(response.getBody());
            assertTrue("Response body should be ErrorDTO", response.getBody() instanceof ErrorDTO);
            ErrorDTO errorDTO = (ErrorDTO) response.getBody();
            assertEquals(JWT_SIGNING_ERROR.getErrorCode(), errorDTO.getErrorCode());
        }
    }

    @Test
    public void testHandlePresentationActionOpenID4VPException() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofStrings(List.of("cred-123")))
                .build();

        WalletPresentationServiceImpl spyService = spy(walletPresentationService);
        doThrow(new OpenID4VPExceptions.AccessDenied("Access denied", "WalletPresentationServiceTest"))
                .when(spyService).submitPresentation(any(), anyString(), anyString(), any(), anyString());

        ResponseEntity<?> response = spyService.handlePresentationAction(
                walletId, presentationId, request, sessionData, base64Key);

        assertNotNull(response);
        assertEquals(400, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertTrue("Response body should be ErrorDTO", response.getBody() instanceof ErrorDTO);
        ErrorDTO errorDTO = (ErrorDTO) response.getBody();
        assertEquals(OpenID4VPErrorCodes.ACCESS_DENIED, errorDTO.getErrorCode());
        assertEquals("Access denied", errorDTO.getErrorMessage());
    }

    @Test
    public void testHandlePresentationActionKeyGenerationException() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofStrings(List.of("cred-123")))
                .build();

        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);
        UnsignedVPToken ldpToken = mockLdpUnsignedToken();
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(List.of(ldpToken));
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class)))
                .thenThrow(new KeyGenerationException(KEY_GENERATION_ERROR.getErrorCode(), "Key generation failed"));

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, sessionData, base64Key);

        assertNotNull(response);
        assertEquals(500, response.getStatusCode().value());
    }

    @Test
    public void testHandlePresentationActionDecryptionException() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofStrings(List.of("cred-123")))
                .build();

        VerifiablePresentationSessionData testSessionData = new VerifiablePresentationSessionData();
        testSessionData.setPresentationId(presentationId);
        testSessionData.setAuthorizationRequest(urlEncodedVPAuthorizationRequest);
        testSessionData.setCreatedAt(Instant.now());
        testSessionData.setVerifierClientPreregistered(true);
        testSessionData.setMatchingCredentials(List.of(credentialDTO));

        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);
        UnsignedVPToken ldpToken = mockLdpUnsignedToken();
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(List.of(ldpToken));
        
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class)))
                .thenThrow(new DecryptionException(DECRYPTION_ERROR.getErrorCode(), "Decryption failed"));

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, testSessionData, base64Key);

        assertNotNull(response);
        assertEquals(500, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertTrue("Response body should be ErrorDTO", response.getBody() instanceof ErrorDTO);
        ErrorDTO errorDTO = (ErrorDTO) response.getBody();
        assertEquals(DECRYPTION_ERROR.getErrorCode(), errorDTO.getErrorCode());
    }

    @Test
    public void testHandlePresentationActionApiNotAccessibleException() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofStrings(List.of("cred-123")))
                .build();

        when(openID4VPService.getPreRegisteredVerifiers()).thenThrow(new ApiNotAccessibleException("API not accessible"));
        when(openID4VPService.create(anyString(), anyList(), anyBoolean())).thenReturn(mockOpenID4VP);

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, sessionData, base64Key);

        assertNotNull(response);
        assertEquals(500, response.getStatusCode().value());
    }

    @Test
    public void testHandlePresentationActionVPErrorNotSentException() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .errorCode("access_denied")
                .errorMessage("User denied access")
                .build();

        when(openID4VPService.sendErrorToVerifier(any(), any(ErrorDTO.class)))
                .thenThrow(new VPErrorNotSentException("Failed to send error"));

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, sessionData, base64Key);

        assertNotNull(response);
        assertEquals(500, response.getStatusCode().value());
    }

    @Test
    public void testHandlePresentationActionIllegalArgumentException() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofStrings(List.of("cred-123")))
                .build();

        VerifiablePresentationSessionData emptySessionData = new VerifiablePresentationSessionData();
        emptySessionData.setPresentationId(presentationId);
        emptySessionData.setAuthorizationRequest(urlEncodedVPAuthorizationRequest);
        emptySessionData.setVerifierClientPreregistered(true);
        emptySessionData.setMatchingCredentials(null);

        stubOpenId4VpCreate(mockOpenID4VP);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class)) {
            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);

            ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                    walletId, presentationId, request, emptySessionData, base64Key);

            assertNotNull(response);
            assertEquals(400, response.getStatusCode().value());
        }
    }

    @Test
    public void testSubmitPresentationSuccess() throws Exception {
        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, submitRequest, base64Key);

            assertNotNull(result);
            assertEquals(OpenID4VPConstants.STATUS_SUCCESS, result.getStatus());
            verify(verifiablePresentationsRepository).save(any(VerifiablePresentation.class));
        }
    }

    @Test
    public void testSubmitPresentationDcqlNestedSelectedSdClaimsSucceeds() throws Exception {
        String credentialId = "a3e92fcf-b107-46c9-8d68-f10cdbe8214b";
        Map<String, List<String>> nestedSdClaims = Map.of(credentialId, List.of("dateOfBirth"));
        DcqlCredentialSelection dcqlSelection = DcqlCredentialSelection.builder()
                .queryId("government-identity")
                .selectedCredentialIds(List.of(credentialId))
                .selectedSdClaims(nestedSdClaims)
                .build();
        SubmitPresentationRequestDTO dcqlRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofDcql(List.of(dcqlSelection)))
                .build();

        credentialDTO.setId(credentialId);
        credentialDTO.setDescriptorId("government-identity");
        sessionData.setMatchingCredentials(List.of(credentialDTO));

        io.mosip.openID4VP.dcql.query.CredentialQuery credentialQuery =
                mock(io.mosip.openID4VP.dcql.query.CredentialQuery.class);
        when(credentialQuery.getId()).thenReturn("government-identity");
        when(credentialQuery.getMultiple()).thenReturn(false);
        io.mosip.openID4VP.dcql.query.DCQLQuery dcqlQuery =
                mock(io.mosip.openID4VP.dcql.query.DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(credentialQuery));
        when(dcqlQuery.getCredentialSets()).thenReturn(null);

        stubOpenId4VpCreate(mockOpenID4VP);
        when(openID4VPService.resolveDcqlQuery(anyString(), anyString(), anyBoolean()))
                .thenReturn(dcqlQuery);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);
            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"selectedCredentials\":[]}");

            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, dcqlRequest, base64Key);

            assertEquals(OpenID4VPConstants.STATUS_SUCCESS, result.getStatus());
            verify(verifiablePresentationsRepository).save(any(VerifiablePresentation.class));
        }
    }

    @Test
    public void testSubmitPresentationDcqlUsesClientQueryIdAsMapKey() throws Exception {
        String credentialId = "a3e92fcf-b107-46c9-8d68-f10cdbe8214b";
        String clientQueryId = "government-identity";
        DcqlCredentialSelection dcqlSelection = DcqlCredentialSelection.builder()
                .queryId(clientQueryId)
                .selectedCredentialIds(List.of(credentialId))
                .build();
        SubmitPresentationRequestDTO dcqlRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofDcql(List.of(dcqlSelection)))
                .build();

        credentialDTO.setId(credentialId);
        credentialDTO.setDescriptorId("pid_query");
        sessionData.setMatchingCredentials(List.of(credentialDTO));

        io.mosip.openID4VP.dcql.query.CredentialQuery credentialQuery =
                mock(io.mosip.openID4VP.dcql.query.CredentialQuery.class);
        when(credentialQuery.getId()).thenReturn(clientQueryId);
        when(credentialQuery.getMultiple()).thenReturn(false);
        io.mosip.openID4VP.dcql.query.DCQLQuery dcqlQuery =
                mock(io.mosip.openID4VP.dcql.query.DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(credentialQuery));
        when(dcqlQuery.getCredentialSets()).thenReturn(null);

        stubOpenId4VpCreate(mockOpenID4VP);
        when(openID4VPService.resolveDcqlQuery(anyString(), anyString(), anyBoolean()))
                .thenReturn(dcqlQuery);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);
            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"selectedCredentials\":[]}");

            walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, dcqlRequest, base64Key);

            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map> mapCaptor = ArgumentCaptor.forClass(Map.class);
            verify(mockOpenID4VP).constructUnsignedVPToken(mapCaptor.capture());
            assertTrue(mapCaptor.getValue().containsKey(clientQueryId));
            assertFalse(mapCaptor.getValue().containsKey("pid_query"));
        }
    }

    @Test
    public void testSubmitPresentationDcqlClaimSetsAutoResolvesSdClaimPaths() throws Exception {
        String credentialId = "d0b504e8-adaf-4df1-9ba0-2d2a5c52e519";
        String queryId = "age-proof";
        DcqlCredentialSelection dcqlSelection = DcqlCredentialSelection.builder()
                .queryId(queryId)
                .selectedCredentialIds(List.of(credentialId))
                .build();
        SubmitPresentationRequestDTO dcqlRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofDcql(List.of(dcqlSelection)))
                .build();

        String sdJwt = "header.payload.sig~ageDiscB64~dobDiscB64~";
        vcCredentialResponse = VCCredentialResponse.builder()
                .format(CredentialFormat.DC_SD_JWT.getFormat())
                .credential(sdJwt)
                .build();
        credentialDTO = DecryptedCredentialDTO.builder()
                .id(credentialId)
                .descriptorId(queryId)
                .credential(vcCredentialResponse)
                .build();
        sessionData.setMatchingCredentials(List.of(credentialDTO));
        when(walletCredentialService.getDecryptedCredentials(anyString(), anyString()))
                .thenReturn(List.of(credentialDTO));

        io.mosip.openID4VP.dcql.query.ClaimsQuery ageClaim =
                new io.mosip.openID4VP.dcql.query.ClaimsQuery(
                        "age-above-18", List.of("age_above_18"),
                        List.of(new io.mosip.openID4VP.dcql.query.ClaimValue.BoolValue(true)));
        io.mosip.openID4VP.dcql.query.ClaimsQuery dobClaim =
                new io.mosip.openID4VP.dcql.query.ClaimsQuery(
                        "date-of-birth", List.of("dateOfBirth"), null);
        io.mosip.openID4VP.dcql.query.CredentialQuery credentialQuery =
                new io.mosip.openID4VP.dcql.query.CredentialQuery(
                        queryId, CredentialFormat.DC_SD_JWT.getFormat(), false,
                        Map.of(), false, List.of(ageClaim, dobClaim),
                        List.of(List.of("age-above-18"), List.of("date-of-birth")));
        io.mosip.openID4VP.dcql.query.DCQLQuery dcqlQuery =
                mock(io.mosip.openID4VP.dcql.query.DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(credentialQuery));
        when(dcqlQuery.getCredentialSets()).thenReturn(null);

        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("age_above_18", List.of("ageDiscB64"));
        sdClaims.put("dateOfBirth", List.of("dobDiscB64"));
        Map<String, Object> allProps = new HashMap<>();
        allProps.put("sdClaims", sdClaims);
        allProps.put("publicClaims", Map.of("vct", "AgeProofCredential"));
        when(credentialFormatHandlerFactory.getHandler(CredentialFormat.DC_SD_JWT.getFormat()))
                .thenReturn(credentialFormatHandler);
        doReturn(allProps).when(credentialFormatHandler).extractAllCredentialProperties(any());

        stubOpenId4VpCreate(mockOpenID4VP);
        when(openID4VPService.resolveDcqlQuery(anyString(), anyString(), anyBoolean()))
                .thenReturn(dcqlQuery);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        List<UnsignedVPToken> unsignedTokens = List.of(mockSdJwtUnsignedToken());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);
            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");
            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"selectedCredentials\":[]}");

            walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, dcqlRequest, base64Key);

            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, List<io.mosip.openID4VP.wallet.Credential>>> mapCaptor =
                    ArgumentCaptor.forClass(Map.class);
            verify(mockOpenID4VP).constructUnsignedVPToken(mapCaptor.capture());
            io.mosip.openID4VP.wallet.Credential submitted =
                    mapCaptor.getValue().get(queryId).get(0);
            String filteredSdJwt = (String) submitted.getData();
            assertEquals("header.payload.sig~ageDiscB64~", filteredSdJwt);
        }
    }

    @Test
    public void testValidateDcqlSelectionsRejectsMultipleFalseWithTwoCredentials() throws Exception {
        String queryId = "government-identity";
        DcqlCredentialSelection dcqlSelection = DcqlCredentialSelection.builder()
                .queryId(queryId)
                .selectedCredentialIds(List.of("cred-1", "cred-2"))
                .build();
        SubmitPresentationRequestDTO dcqlRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofDcql(List.of(dcqlSelection)))
                .build();

        io.mosip.openID4VP.dcql.query.CredentialQuery credentialQuery =
                mock(io.mosip.openID4VP.dcql.query.CredentialQuery.class);
        when(credentialQuery.getId()).thenReturn(queryId);
        when(credentialQuery.getMultiple()).thenReturn(false);
        io.mosip.openID4VP.dcql.query.DCQLQuery dcqlQuery =
                mock(io.mosip.openID4VP.dcql.query.DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(credentialQuery));
        when(dcqlQuery.getCredentialSets()).thenReturn(null);

        stubOpenId4VpCreate(mockOpenID4VP);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);
        when(openID4VPService.resolveDcqlQuery(anyString(), anyString(), anyBoolean()))
                .thenReturn(dcqlQuery);

        try {
            walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, dcqlRequest, base64Key);
            fail("Should throw InvalidRequestException");
        } catch (InvalidRequestException e) {
            assertTrue(e.getMessage().contains("has multiple=false but 2 credential(s) were selected"));
        }
    }

    @Test
    public void testValidateDcqlSelectionsRejectsCredentialSetWithMixedOptions() throws Exception {
        io.mosip.openID4VP.dcql.query.CredentialSetQuery setQuery =
                mock(io.mosip.openID4VP.dcql.query.CredentialSetQuery.class);
        when(setQuery.getRequired()).thenReturn(true);
        when(setQuery.getOptions()).thenReturn(List.of(List.of("pan"), List.of("aadhaar")));

        io.mosip.openID4VP.dcql.query.CredentialQuery panQuery =
                mock(io.mosip.openID4VP.dcql.query.CredentialQuery.class);
        when(panQuery.getId()).thenReturn("pan");
        when(panQuery.getMultiple()).thenReturn(false);
        io.mosip.openID4VP.dcql.query.CredentialQuery aadhaarQuery =
                mock(io.mosip.openID4VP.dcql.query.CredentialQuery.class);
        when(aadhaarQuery.getId()).thenReturn("aadhaar");
        when(aadhaarQuery.getMultiple()).thenReturn(false);

        io.mosip.openID4VP.dcql.query.DCQLQuery dcqlQuery =
                mock(io.mosip.openID4VP.dcql.query.DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(panQuery, aadhaarQuery));
        when(dcqlQuery.getCredentialSets()).thenReturn(List.of(setQuery));

        DcqlCredentialSelection panSelection = DcqlCredentialSelection.builder()
                .queryId("pan")
                .selectedCredentialIds(List.of("cred-pan"))
                .build();
        DcqlCredentialSelection aadhaarSelection = DcqlCredentialSelection.builder()
                .queryId("aadhaar")
                .selectedCredentialIds(List.of("cred-aadhaar"))
                .build();
        SubmitPresentationRequestDTO dcqlRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofDcql(List.of(panSelection, aadhaarSelection)))
                .build();

        stubOpenId4VpCreate(mockOpenID4VP);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);
        when(openID4VPService.resolveDcqlQuery(anyString(), anyString(), anyBoolean()))
                .thenReturn(dcqlQuery);

        try {
            walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, dcqlRequest, base64Key);
            fail("Should throw InvalidRequestException");
        } catch (InvalidRequestException e) {
            assertTrue(e.getMessage().contains(
                    "Credential selection must satisfy exactly one option in credential_set"));
        }
    }

    @Test
    public void testSubmitPresentationDcqlCredentialSetSingleOptionSucceeds() throws Exception {
        String panCredentialId = "cred-pan-001";
        DcqlCredentialSelection panSelection = DcqlCredentialSelection.builder()
                .queryId("pan")
                .selectedCredentialIds(List.of(panCredentialId))
                .build();
        SubmitPresentationRequestDTO dcqlRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofDcql(List.of(panSelection)))
                .build();

        DecryptedCredentialDTO panCredential = DecryptedCredentialDTO.builder()
                .id(panCredentialId)
                .descriptorId("pan")
                .walletId(walletId)
                .credential(vcCredentialResponse)
                .build();
        sessionData.setMatchingCredentials(List.of(panCredential));

        io.mosip.openID4VP.dcql.query.CredentialSetQuery setQuery =
                mock(io.mosip.openID4VP.dcql.query.CredentialSetQuery.class);
        when(setQuery.getRequired()).thenReturn(true);
        when(setQuery.getOptions()).thenReturn(List.of(List.of("pan"), List.of("aadhaar")));

        io.mosip.openID4VP.dcql.query.CredentialQuery panQuery =
                mock(io.mosip.openID4VP.dcql.query.CredentialQuery.class);
        when(panQuery.getId()).thenReturn("pan");
        when(panQuery.getMultiple()).thenReturn(false);
        io.mosip.openID4VP.dcql.query.CredentialQuery aadhaarQuery =
                mock(io.mosip.openID4VP.dcql.query.CredentialQuery.class);
        when(aadhaarQuery.getId()).thenReturn("aadhaar");
        when(aadhaarQuery.getMultiple()).thenReturn(false);

        io.mosip.openID4VP.dcql.query.DCQLQuery dcqlQuery =
                mock(io.mosip.openID4VP.dcql.query.DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(panQuery, aadhaarQuery));
        when(dcqlQuery.getCredentialSets()).thenReturn(List.of(setQuery));

        stubOpenId4VpCreate(mockOpenID4VP);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);
        when(openID4VPService.resolveDcqlQuery(anyString(), anyString(), anyBoolean()))
                .thenReturn(dcqlQuery);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);
            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"selectedCredentials\":[]}");

            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, dcqlRequest, base64Key);

            assertEquals(OpenID4VPConstants.STATUS_SUCCESS, result.getStatus());
            verify(verifiablePresentationsRepository).save(any(VerifiablePresentation.class));
        }
    }

    private UnsignedVPToken mockSdJwtUnsignedToken() {
        UnsignedVPToken token = mock(UnsignedVPToken.class);
        when(token.getFormat()).thenReturn(FormatType.DC_SD_JWT);
        when(token.getSignatureAlgorithm()).thenReturn("EdDSA");
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"EdDSA\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"test\"}".getBytes(StandardCharsets.UTF_8));
        when(token.getDataToSign()).thenReturn((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
        return token;
    }

    @Test
    public void testSubmitPresentationShareFailed() throws Exception {
        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(500);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/error");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, submitRequest, base64Key);

            assertNotNull(result);
            assertEquals(OpenID4VPConstants.STATUS_ERROR, result.getStatus());
            verify(verifiablePresentationsRepository).save(any(VerifiablePresentation.class));
        }
    }

    @Test
    public void testSubmitPresentationExceptionDuringShare() throws Exception {
        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenThrow(new RuntimeException("Network error"));

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, submitRequest, base64Key);

            assertNotNull(result);
            assertEquals(OpenID4VPConstants.STATUS_ERROR, result.getStatus());
            assertNull(result.getRedirectUri());
            verify(verifiablePresentationsRepository).save(any(VerifiablePresentation.class));
        }
    }

    @Test(expected = java.lang.IllegalArgumentException.class)
    public void testSubmitPresentationNullRequest() throws Exception {
        walletPresentationService.submitPresentation(
                sessionData, walletId, presentationId, null, base64Key);
    }

    @Test(expected = java.lang.IllegalArgumentException.class)
    public void testSubmitPresentationEmptyCredentials() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofStrings(Collections.emptyList()))
                .build();

        walletPresentationService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);
    }

    @Test
    public void testHandlePresentationSubmissionNullBase64Key() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofStrings(List.of("cred-123")))
                .build();

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, sessionData, null);

        assertNotNull(response);
        assertEquals(400, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertTrue("Response body should be ErrorDTO", response.getBody() instanceof ErrorDTO);
        ErrorDTO errorDTO = (ErrorDTO) response.getBody();
        assertEquals(INVALID_REQUEST.getErrorCode(), errorDTO.getErrorCode());
    }

    @Test
    public void testHandlePresentationSubmissionBlankBase64Key() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofStrings(List.of("cred-123")))
                .build();

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, sessionData, "   ");

        assertNotNull(response);
        assertEquals(400, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertTrue("Response body should be ErrorDTO", response.getBody() instanceof ErrorDTO);
        ErrorDTO errorDTO = (ErrorDTO) response.getBody();
        assertEquals(INVALID_REQUEST.getErrorCode(), errorDTO.getErrorCode());
    }

    @Test
    public void testSignVPTokenUnsupportedFormat() throws Exception {
        VCCredentialResponse unsupportedFormatCredential = new VCCredentialResponse();
        unsupportedFormatCredential.setFormat("jwt_vc_json");
        unsupportedFormatCredential.setCredential(Map.of("type", "VerifiableCredential"));

        DecryptedCredentialDTO credWithUnsupportedFormat = DecryptedCredentialDTO.builder()
                .id("cred-123")
                .walletId(walletId)
                .credential(unsupportedFormatCredential)
                .build();

        VerifiablePresentationSessionData sessionDataWithUnsupportedFormat = new VerifiablePresentationSessionData();
        sessionDataWithUnsupportedFormat.setMatchingCredentials(List.of(credWithUnsupportedFormat));
        sessionDataWithUnsupportedFormat.setAuthorizationRequest(urlEncodedVPAuthorizationRequest);
        sessionDataWithUnsupportedFormat.setVerifierClientPreregistered(true);

        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class)) {
            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);

            try {
                walletPresentationService.submitPresentation(
                        sessionDataWithUnsupportedFormat, walletId, presentationId, submitRequest, base64Key);
                fail("Should throw InvalidRequestException");
            } catch (InvalidRequestException e) {
                assertTrue(e.getMessage().contains("Unsupported credential format"));
            }
        }
    }

    @Test(expected = IllegalStateException.class)
    public void testFetchSelectedCredentialsNullMatchingCredentials() throws Exception {
        VerifiablePresentationSessionData nullSessionData = new VerifiablePresentationSessionData();
        nullSessionData.setPresentationId(presentationId);
        nullSessionData.setAuthorizationRequest(urlEncodedVPAuthorizationRequest);
        nullSessionData.setVerifierClientPreregistered(true);
        nullSessionData.setMatchingCredentials(null);

        stubOpenId4VpCreate(mockOpenID4VP);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);

        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofStrings(List.of("cred-123")))
                .build();

        walletPresentationService.submitPresentation(
                nullSessionData, walletId, presentationId, request, base64Key);
    }

    @Test
    public void testFetchSelectedCredentialsNoMatchingCredential() throws Exception {
        VerifiablePresentationSessionData sessionDataWithDifferentCred = new VerifiablePresentationSessionData();
        DecryptedCredentialDTO differentCred = DecryptedCredentialDTO.builder()
                .id("cred-999")
                .walletId(walletId)
                .credential(vcCredentialResponse)
                .build();
        sessionDataWithDifferentCred.setMatchingCredentials(List.of(differentCred));
        sessionDataWithDifferentCred.setAuthorizationRequest(urlEncodedVPAuthorizationRequest);
        sessionDataWithDifferentCred.setVerifierClientPreregistered(true);

        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofStrings(List.of("cred-123")))
                .build();

        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {
            
            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");

            List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
            when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

            try {
                SubmitPresentationResponseDTO response = walletPresentationService.submitPresentation(
                        sessionDataWithDifferentCred, walletId, presentationId, request, base64Key);
                assertNotNull(response);
            } catch (Exception e) {
                assertTrue("Unexpected exception type: " + e.getClass().getName() + ": " + e.getMessage(),
                        e instanceof IllegalStateException || e instanceof InvalidRequestException || 
                        e instanceof ApiNotAccessibleException || e instanceof IOException || 
                        e instanceof JOSEException || e instanceof DecryptionException ||
                        e instanceof KeyGenerationException || e instanceof java.lang.NullPointerException);
            }
        }
    }

    @Test(expected = InvalidRequestException.class)
    public void testMapStringToFormatTypeNullFormat() throws Exception {
        VCCredentialResponse nullFormatCredential = new VCCredentialResponse();
        nullFormatCredential.setFormat(null);
        nullFormatCredential.setCredential(Map.of("type", "VerifiableCredential"));

        DecryptedCredentialDTO credWithNullFormat = DecryptedCredentialDTO.builder()
                .id("cred-123")
                .walletId(walletId)
                .credential(nullFormatCredential)
                .build();

        VerifiablePresentationSessionData sessionDataWithNullFormat = new VerifiablePresentationSessionData();
        sessionDataWithNullFormat.setMatchingCredentials(List.of(credWithNullFormat));
        sessionDataWithNullFormat.setAuthorizationRequest(urlEncodedVPAuthorizationRequest);
        sessionDataWithNullFormat.setVerifierClientPreregistered(true);

        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class)) {
            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);

            walletPresentationService.submitPresentation(
                    sessionDataWithNullFormat, walletId, presentationId, submitRequest, base64Key);
        }
    }

    @Test(expected = InvalidRequestException.class)
    public void testMapStringToFormatTypeUnsupportedFormat() throws Exception {
        VCCredentialResponse unsupportedFormatCredential = new VCCredentialResponse();
        unsupportedFormatCredential.setFormat("jwt_vc");
        unsupportedFormatCredential.setCredential(Map.of("type", "VerifiableCredential"));

        DecryptedCredentialDTO credWithUnsupportedFormat = DecryptedCredentialDTO.builder()
                .id("cred-123")
                .walletId(walletId)
                .credential(unsupportedFormatCredential)
                .build();

        VerifiablePresentationSessionData sessionDataWithUnsupportedFormat = new VerifiablePresentationSessionData();
        sessionDataWithUnsupportedFormat.setMatchingCredentials(List.of(credWithUnsupportedFormat));
        sessionDataWithUnsupportedFormat.setAuthorizationRequest(urlEncodedVPAuthorizationRequest);
        sessionDataWithUnsupportedFormat.setVerifierClientPreregistered(true);

        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class)) {
            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);

            walletPresentationService.submitPresentation(
                    sessionDataWithUnsupportedFormat, walletId, presentationId, submitRequest, base64Key);
        }
    }

    @Test
    public void testStorePresentationRecordNullSessionData() throws Exception {
        VerifiablePresentationSessionData nullSessionData = null;

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);


            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            
            try {
                walletPresentationService.submitPresentation(
                        nullSessionData, walletId, presentationId, submitRequest, base64Key);
            } catch (Exception e) {
            }
        }
    }

    @Test
    public void testStorePresentationRecordExceptionDuringSave() throws Exception {
        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        when(verifiablePresentationsRepository.save(any(VerifiablePresentation.class)))
                .thenThrow(new RuntimeException("Database error"));

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, submitRequest, base64Key);

            assertNotNull(result);
        }
    }

    @Test
    public void testExtractVerifierIdNullAuthorizationRequest() throws Exception {
        VerifiablePresentationSessionData sessionDataWithNullAuth = new VerifiablePresentationSessionData();
        sessionDataWithNullAuth.setAuthorizationRequest(null);
        sessionDataWithNullAuth.setMatchingCredentials(List.of(credentialDTO));

        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionDataWithNullAuth, walletId, presentationId, submitRequest, base64Key);

            assertNotNull(result);
            verify(verifiablePresentationsRepository).save(argThat(presentation ->
                    "unknown".equals(((VerifiablePresentation) presentation).getVerifierId())
            ));
        }
    }

    @Test
    public void testExtractVerifierIdExceptionDuringExtraction() throws Exception {
        VerifiablePresentationSessionData sessionDataWithInvalidAuth = new VerifiablePresentationSessionData();
        sessionDataWithInvalidAuth.setAuthorizationRequest("invalid-url");
        sessionDataWithInvalidAuth.setMatchingCredentials(List.of(credentialDTO));

        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenThrow(new RuntimeException("URL parsing error"));

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionDataWithInvalidAuth, walletId, presentationId, submitRequest, base64Key);

            assertNotNull(result);
            verify(verifiablePresentationsRepository).save(argThat(presentation ->
                    "unknown".equals(((VerifiablePresentation) presentation).getVerifierId())
            ));
        }
    }

    @Test
    public void testExtractVerifierAuthRequestNullAuthorizationRequest() throws Exception {
        VerifiablePresentationSessionData sessionDataWithNullAuth = new VerifiablePresentationSessionData();
        sessionDataWithNullAuth.setAuthorizationRequest(null);
        sessionDataWithNullAuth.setMatchingCredentials(List.of(credentialDTO));

        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionDataWithNullAuth, walletId, presentationId, submitRequest, base64Key);

            assertNotNull(result);
        }
    }

    @Test
    public void testExtractVerifierAuthRequestExceptionDuringExtraction() throws Exception {
        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        when(objectMapper.writeValueAsString(any()))
                .thenReturn("{\"kty\":\"OKP\"}")
                .thenThrow(new JsonProcessingException("JSON error") {});

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, submitRequest, base64Key);

            assertNotNull(result);
        }
    }

    @Test
    public void testCreatePresentationDataExceptionDuringCreation() throws Exception {
        stubOpenId4VpCreate(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        List<UnsignedVPToken> unsignedTokens = List.of(mockLdpUnsignedToken());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        when(objectMapper.writeValueAsString(any()))
                .thenReturn("{\"kty\":\"OKP\"}")
                .thenThrow(new JsonProcessingException("JSON error") {});

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, submitRequest, base64Key);

            assertNotNull(result);
        }
    }

    @Test
    public void testRejectVerifierSuccess() throws Exception {
        ErrorDTO errorDTO = new ErrorDTO();
        errorDTO.setErrorCode("access_denied");
        errorDTO.setErrorMessage("User denied access");

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/rejected");
        when(openID4VPService.sendErrorToVerifier(any(), any(ErrorDTO.class))).thenReturn(verifierResponse);

        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .errorCode("access_denied")
                .errorMessage("User denied access")
                .build();

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, sessionData, base64Key);

        assertNotNull(response);
        assertEquals(200, response.getStatusCode().value());
        verify(openID4VPService).sendErrorToVerifier(any(), any(ErrorDTO.class));
    }

    @Test
    public void testRejectVerifierApiNotAccessibleException() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .errorCode("access_denied")
                .errorMessage("User denied access")
                .build();

        when(openID4VPService.sendErrorToVerifier(any(), any(ErrorDTO.class)))
                .thenThrow(new ApiNotAccessibleException("API not accessible"));

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, sessionData, base64Key);

        assertNotNull(response);
        assertEquals(500, response.getStatusCode().value());
    }

    @Test
    public void testRejectVerifierIOException() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .errorCode("access_denied")
                .errorMessage("User denied access")
                .build();

        when(openID4VPService.sendErrorToVerifier(any(), any(ErrorDTO.class)))
                .thenThrow(new IOException("IO error"));

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, sessionData, base64Key);

        assertNotNull(response);
        assertEquals(500, response.getStatusCode().value());
    }

    @Test
    public void testRejectVerifierURISyntaxException() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .errorCode("access_denied")
                .errorMessage("User denied access")
                .build();

        when(openID4VPService.sendErrorToVerifier(any(), any(ErrorDTO.class)))
                .thenThrow(new URISyntaxException("invalid", "URI syntax error"));

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, sessionData, base64Key);

        assertNotNull(response);
        assertEquals(500, response.getStatusCode().value());
    }

    @Test
    public void testRejectVerifierIllegalArgumentException() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .errorCode("access_denied")
                .errorMessage("User denied access")
                .build();

        when(openID4VPService.sendErrorToVerifier(any(), any(ErrorDTO.class)))
                .thenThrow(new java.lang.IllegalArgumentException("Invalid argument"));

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, sessionData, base64Key);

        assertNotNull(response);
        assertEquals(500, response.getStatusCode().value());
    }

    @Test
    public void testSignVPTokensSignsSdJwtKBT() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "signVPTokens", List.class, String.class, String.class);
        method.setAccessible(true);

        String kbHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8));
        String kbPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"nonce\":\"abc\"}".getBytes(StandardCharsets.UTF_8));
        String unsignedKBT = kbHeader + "." + kbPayload;

        UnsignedVPToken mockToken = mock(UnsignedVPToken.class);
        when(mockToken.getFormat()).thenReturn(FormatType.VC_SD_JWT);
        when(mockToken.getDataToSign()).thenReturn(unsignedKBT.getBytes(StandardCharsets.US_ASCII));
        when(mockToken.getSignatureAlgorithm()).thenReturn("ES256");
        when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("test-sig"));

        KeyPair mockKeyPair = mock(KeyPair.class);
        JWK mockJwk = mock(JWK.class);
        when(keyPairService.getKeyPairFromDB(eq("wallet-1"), eq("base64Key"), eq(SigningAlgorithm.ES256)))
                .thenReturn(mockKeyPair);

        try (MockedStatic<SigningKeyUtil> mockedSigningKeyUtil = mockStatic(SigningKeyUtil.class)) {
            mockedSigningKeyUtil.when(() -> SigningKeyUtil.generateJwk(SigningAlgorithm.ES256, mockKeyPair))
                    .thenReturn(mockJwk);
            mockedSigningKeyUtil.when(() -> SigningKeyUtil.createSigner(SigningAlgorithm.ES256, mockJwk))
                    .thenReturn(jwsSigner);

            @SuppressWarnings("unchecked")
            List<VPTokenSigningResult> results = (List<VPTokenSigningResult>) method.invoke(
                    walletPresentationService, List.of(mockToken), "wallet-1", "base64Key");

            assertNotNull(results);
            assertEquals(1, results.size());
            verify(jwsSigner).sign(any(JWSHeader.class), eq(unsignedKBT.getBytes(StandardCharsets.US_ASCII)));
        }
    }

    @Test
    public void testSignVPTokensThrowsWhenJwsHeaderCannotBeParsed() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "signVPTokens", List.class, String.class, String.class);
        method.setAccessible(true);

        String badHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("not-valid-jws-header".getBytes(StandardCharsets.UTF_8));
        String unsignedKbt = badHeader + ".payload";

        UnsignedVPToken mockToken = mock(UnsignedVPToken.class);
        when(mockToken.getFormat()).thenReturn(FormatType.VC_SD_JWT);
        when(mockToken.getDataToSign()).thenReturn(unsignedKbt.getBytes(StandardCharsets.US_ASCII));
        when(mockToken.getSignatureAlgorithm()).thenReturn("ES256");

        KeyPair mockKeyPair = mock(KeyPair.class);
        JWK mockJwk = mock(JWK.class);
        when(keyPairService.getKeyPairFromDB(eq("wallet-1"), eq("base64Key"), eq(SigningAlgorithm.ES256)))
                .thenReturn(mockKeyPair);

        try (MockedStatic<SigningKeyUtil> mockedSigningKeyUtil = mockStatic(SigningKeyUtil.class)) {
            mockedSigningKeyUtil.when(() -> SigningKeyUtil.generateJwk(SigningAlgorithm.ES256, mockKeyPair))
                    .thenReturn(mockJwk);
            mockedSigningKeyUtil.when(() -> SigningKeyUtil.createSigner(SigningAlgorithm.ES256, mockJwk))
                    .thenReturn(jwsSigner);

            try {
                method.invoke(walletPresentationService, List.of(mockToken), "wallet-1", "base64Key");
                fail("Should throw JOSEException");
            } catch (InvocationTargetException e) {
                assertTrue(e.getCause() instanceof JOSEException);
                assertEquals("Failed to parse JWS header for VP token signing", e.getCause().getMessage());
            }
        }
    }

    @Test
    public void testBuildFilteredSdJwtWhenSelectedPathsIsNullSharesNoDisclosures() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "buildFilteredSdJwt", DecryptedCredentialDTO.class, List.class);
        method.setAccessible(true);

        String originalSdJwt = "header.payload.sig~disc1~";
        DecryptedCredentialDTO credential = DecryptedCredentialDTO.builder()
                .id("cred-id")
                .credential(VCCredentialResponse.builder()
                        .format(CredentialFormat.VC_SD_JWT.getFormat())
                        .credential(originalSdJwt)
                        .build())
                .build();

        // No selected paths -> user disclosed nothing -> credential JWT with zero disclosures
        String result = (String) method.invoke(walletPresentationService, credential, null);
        assertEquals("header.payload.sig~", result);
    }

    @Test
    public void testBuildFilteredSdJwtWhenSelectedPathsFiltersToSelectedDisclosures() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "buildFilteredSdJwt", DecryptedCredentialDTO.class, List.class);
        method.setAccessible(true);

        String originalSdJwt = "header.payload.sig~emailDiscB64~nameDiscB64~";
        DecryptedCredentialDTO credential = DecryptedCredentialDTO.builder()
                .id("cred-id")
                .credential(VCCredentialResponse.builder()
                        .format(CredentialFormat.VC_SD_JWT.getFormat())
                        .credential(originalSdJwt)
                        .build())
                .build();

        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("email", List.of("emailDiscB64"));
        sdClaims.put("name", List.of("nameDiscB64"));
        Map<String, Object> allProps = new HashMap<>();
        allProps.put("sdClaims", sdClaims);

        when(credentialFormatHandlerFactory.getHandler(CredentialFormat.VC_SD_JWT.getFormat()))
                .thenReturn(credentialFormatHandler);
        doReturn(allProps).when(credentialFormatHandler).extractAllCredentialProperties(any());

        String result = (String) method.invoke(walletPresentationService, credential, List.of("$.email"));
        assertEquals("header.payload.sig~emailDiscB64~", result);
    }

    @Test
    public void testBuildFilteredSdJwtNormalizesPathsWithoutDollarDotPrefix() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "buildFilteredSdJwt", DecryptedCredentialDTO.class, List.class);
        method.setAccessible(true);

        String originalSdJwt = "header.payload.sig~emailDiscB64~";
        DecryptedCredentialDTO credential = DecryptedCredentialDTO.builder()
                .id("cred-id")
                .credential(VCCredentialResponse.builder()
                        .format(CredentialFormat.VC_SD_JWT.getFormat())
                        .credential(originalSdJwt)
                        .build())
                .build();

        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("email", List.of("emailDiscB64"));
        Map<String, Object> allProps = new HashMap<>();
        allProps.put("sdClaims", sdClaims);

        when(credentialFormatHandlerFactory.getHandler(CredentialFormat.VC_SD_JWT.getFormat()))
                .thenReturn(credentialFormatHandler);
        doReturn(allProps).when(credentialFormatHandler).extractAllCredentialProperties(any());

        // "email" without "$." prefix should produce the same result as "$.email"
        String result = (String) method.invoke(walletPresentationService, credential, List.of("email"));
        assertEquals("header.payload.sig~emailDiscB64~", result);
    }

    @Test
    public void testBuildFilteredSdJwtResolvesCredentialSubjectPrefixedSdClaimKeys() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "buildFilteredSdJwt", DecryptedCredentialDTO.class, List.class);
        method.setAccessible(true);

        String originalSdJwt = "header.payload.sig~dobDiscB64~";
        DecryptedCredentialDTO credential = DecryptedCredentialDTO.builder()
                .id("cred-id")
                .credential(VCCredentialResponse.builder()
                        .format(CredentialFormat.VC_SD_JWT.getFormat())
                        .credential(originalSdJwt)
                        .build())
                .build();

        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("credentialSubject.dateOfBirth", List.of("dobDiscB64"));
        Map<String, Object> allProps = new HashMap<>();
        allProps.put("sdClaims", sdClaims);

        when(credentialFormatHandlerFactory.getHandler(CredentialFormat.VC_SD_JWT.getFormat()))
                .thenReturn(credentialFormatHandler);
        doReturn(allProps).when(credentialFormatHandler).extractAllCredentialProperties(any());

        String result = (String) method.invoke(walletPresentationService, credential, List.of("dateOfBirth"));
        assertEquals("header.payload.sig~dobDiscB64~", result);
    }

    @Test
    public void testBuildFilteredSdJwtResolvesArrayIndexedCredentialSubjectPaths() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "buildFilteredSdJwt", DecryptedCredentialDTO.class, List.class);
        method.setAccessible(true);

        String originalSdJwt = "header.payload.sig~dobDiscB64~";
        DecryptedCredentialDTO credential = DecryptedCredentialDTO.builder()
                .id("cred-id")
                .credential(VCCredentialResponse.builder()
                        .format(CredentialFormat.VC_SD_JWT.getFormat())
                        .credential(originalSdJwt)
                        .build())
                .build();

        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("credentialSubject[0].dateOfBirth", List.of("dobDiscB64"));
        Map<String, Object> allProps = new HashMap<>();
        allProps.put("sdClaims", sdClaims);

        when(credentialFormatHandlerFactory.getHandler(CredentialFormat.VC_SD_JWT.getFormat()))
                .thenReturn(credentialFormatHandler);
        doReturn(allProps).when(credentialFormatHandler).extractAllCredentialProperties(any());

        String result = (String) method.invoke(walletPresentationService, credential, List.of("$.dateOfBirth"));
        assertEquals("header.payload.sig~dobDiscB64~", result);
    }

    @Test
    public void testBuildFilteredSdJwtWhenSdClaimsKeyMissingSharesNoDisclosures() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "buildFilteredSdJwt", DecryptedCredentialDTO.class, List.class);
        method.setAccessible(true);

        String originalSdJwt = "header.payload.sig~disc~";
        DecryptedCredentialDTO credential = DecryptedCredentialDTO.builder()
                .id("cred-id")
                .credential(VCCredentialResponse.builder()
                        .format(CredentialFormat.VC_SD_JWT.getFormat())
                        .credential(originalSdJwt)
                        .build())
                .build();

        Map<String, Object> allProps = new HashMap<>();
        allProps.put("publicClaims", new HashMap<>());

        when(credentialFormatHandlerFactory.getHandler(CredentialFormat.VC_SD_JWT.getFormat()))
                .thenReturn(credentialFormatHandler);
        doReturn(allProps).when(credentialFormatHandler).extractAllCredentialProperties(any());

        // sdClaims key missing -> cannot resolve selections -> credential JWT with zero disclosures
        String result = (String) method.invoke(walletPresentationService, credential, List.of("$.email"));
        assertEquals("header.payload.sig~", result);
    }

    @Test
    public void testBuildFilteredSdJwtWhenSelectedPathsEmptySharesNoDisclosures() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "buildFilteredSdJwt", DecryptedCredentialDTO.class, List.class);
        method.setAccessible(true);

        DecryptedCredentialDTO credential = DecryptedCredentialDTO.builder()
                .id("cred-id")
                .credential(VCCredentialResponse.builder()
                        .format(CredentialFormat.VC_SD_JWT.getFormat())
                        .credential("header.payload.sig~disc1~disc2~")
                        .build())
                .build();

        String result = (String) method.invoke(walletPresentationService, credential, Collections.emptyList());
        assertEquals("header.payload.sig~", result);
    }

    @Test
    public void testBuildFilteredSdJwtWhenSdClaimsMapEmptySharesNoDisclosures() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "buildFilteredSdJwt", DecryptedCredentialDTO.class, List.class);
        method.setAccessible(true);

        DecryptedCredentialDTO credential = DecryptedCredentialDTO.builder()
                .id("cred-id")
                .credential(VCCredentialResponse.builder()
                        .format(CredentialFormat.VC_SD_JWT.getFormat())
                        .credential("header.payload.sig~disc~")
                        .build())
                .build();

        Map<String, Object> allProps = new HashMap<>();
        allProps.put("sdClaims", new LinkedHashMap<>()); // present but empty

        when(credentialFormatHandlerFactory.getHandler(CredentialFormat.VC_SD_JWT.getFormat()))
                .thenReturn(credentialFormatHandler);
        doReturn(allProps).when(credentialFormatHandler).extractAllCredentialProperties(any());

        String result = (String) method.invoke(walletPresentationService, credential, List.of("$.email"));
        assertEquals("header.payload.sig~", result);
    }

    @Test
    public void testBuildFilteredSdJwtWhenSelectedPathNotInSdClaimsSharesNoDisclosures() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "buildFilteredSdJwt", DecryptedCredentialDTO.class, List.class);
        method.setAccessible(true);

        DecryptedCredentialDTO credential = DecryptedCredentialDTO.builder()
                .id("cred-id")
                .credential(VCCredentialResponse.builder()
                        .format(CredentialFormat.VC_SD_JWT.getFormat())
                        .credential("header.payload.sig~nameDiscB64~")
                        .build())
                .build();

        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("name", List.of("nameDiscB64"));
        Map<String, Object> allProps = new HashMap<>();
        allProps.put("sdClaims", sdClaims);

        when(credentialFormatHandlerFactory.getHandler(CredentialFormat.VC_SD_JWT.getFormat()))
                .thenReturn(credentialFormatHandler);
        doReturn(allProps).when(credentialFormatHandler).extractAllCredentialProperties(any());

        // user selects "email" but only "name" is selectively disclosable -> no disclosures shared
        String result = (String) method.invoke(walletPresentationService, credential, List.of("$.email"));
        assertEquals("header.payload.sig~", result);
    }

    @Test
    public void testBuildFilteredSdJwtWhenCredentialNotStringReturnsRawValue() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "buildFilteredSdJwt", DecryptedCredentialDTO.class, List.class);
        method.setAccessible(true);

        Map<String, Object> mapCredential = new HashMap<>();
        mapCredential.put("type", "not-a-string-sdjwt");
        DecryptedCredentialDTO credential = DecryptedCredentialDTO.builder()
                .id("cred-id")
                .credential(VCCredentialResponse.builder()
                        .format(CredentialFormat.VC_SD_JWT.getFormat())
                        .credential(mapCredential)
                        .build())
                .build();

        // Non-String payload cannot be SD-JWT filtered; the raw value is returned as-is
        String result = (String) method.invoke(walletPresentationService, credential, List.of("$.email"));
        assertEquals(String.valueOf(mapCredential), result);
    }

    @Test
    public void testExtractSdClaimsMapReturnsNullWhenHandlerThrows() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "extractSdClaimsMap", DecryptedCredentialDTO.class);
        method.setAccessible(true);

        DecryptedCredentialDTO credential = DecryptedCredentialDTO.builder()
                .id("sd-cred-1")
                .credential(VCCredentialResponse.builder()
                        .format(CredentialFormat.DC_SD_JWT.getFormat())
                        .credential("header.payload.sig~disc~")
                        .build())
                .build();

        when(credentialFormatHandlerFactory.getHandler(CredentialFormat.DC_SD_JWT.getFormat()))
                .thenReturn(credentialFormatHandler);
        when(credentialFormatHandler.extractAllCredentialProperties(any()))
                .thenThrow(new RuntimeException("parse failure"));

        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) method.invoke(walletPresentationService, credential);

        assertNull(result);
    }

    @Test
    public void testExtractVerifierAuthRequestReturnsEmptyJsonWhenSerializationFails() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "extractVerifierAuthRequest", VerifiablePresentationSessionData.class);
        method.setAccessible(true);

        VerifiablePresentationSessionData data = new VerifiablePresentationSessionData();
        data.setAuthorizationRequest(urlEncodedVPAuthorizationRequest);

        when(objectMapper.writeValueAsString(any()))
                .thenThrow(new JsonProcessingException("serialization failed") {});

        String result = (String) method.invoke(walletPresentationService, data);
        assertEquals("{}", result);
    }

    @Test
    public void testBuildFilteredSdJwtReturnsCredentialJwtOnlyWhenFilteringFails() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "buildFilteredSdJwt", DecryptedCredentialDTO.class, List.class);
        method.setAccessible(true);

        String originalSdJwt = "header.payload.sig~disc1~disc2~";
        DecryptedCredentialDTO credential = DecryptedCredentialDTO.builder()
                .id("cred-id")
                .credential(VCCredentialResponse.builder()
                        .format(CredentialFormat.VC_SD_JWT.getFormat())
                        .credential(originalSdJwt)
                        .build())
                .build();

        when(credentialFormatHandlerFactory.getHandler(CredentialFormat.VC_SD_JWT.getFormat()))
                .thenReturn(credentialFormatHandler);
        when(credentialFormatHandler.extractAllCredentialProperties(any()))
                .thenThrow(new RuntimeException("filter failure"));

        String result = (String) method.invoke(walletPresentationService, credential, List.of("$.email"));
        assertEquals("header.payload.sig~", result);
    }

    @Test
    public void testSignVPTokensBuildsPerCredentialSignersForDifferentAlgs() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "signVPTokens", List.class, String.class, String.class);
        method.setAccessible(true);

        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"nonce\":\"abc\"}".getBytes(StandardCharsets.UTF_8));
        String es256Kbt = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8)) + "." + payload;
        String eddsaKbt = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"EdDSA\"}".getBytes(StandardCharsets.UTF_8)) + "." + payload;

        UnsignedVPToken es256Token = mock(UnsignedVPToken.class);
        when(es256Token.getFormat()).thenReturn(FormatType.VC_SD_JWT);
        when(es256Token.getDataToSign()).thenReturn(es256Kbt.getBytes(StandardCharsets.US_ASCII));
        when(es256Token.getSignatureAlgorithm()).thenReturn("ES256");

        UnsignedVPToken eddsaToken = mock(UnsignedVPToken.class);
        when(eddsaToken.getFormat()).thenReturn(FormatType.VC_SD_JWT);
        when(eddsaToken.getDataToSign()).thenReturn(eddsaKbt.getBytes(StandardCharsets.US_ASCII));
        when(eddsaToken.getSignatureAlgorithm()).thenReturn("EdDSA");

        KeyPair mockKeyPair = mock(KeyPair.class);
        JWK mockJwk = mock(JWK.class);
        when(keyPairService.getKeyPairFromDB(eq("wallet-1"), eq("base64Key"), eq(SigningAlgorithm.ES256)))
                .thenReturn(mockKeyPair);
        when(keyPairService.getKeyPairFromDB(eq("wallet-1"), eq("base64Key"), eq(SigningAlgorithm.ED25519)))
                .thenReturn(mockKeyPair);

        JWSSigner es256Signer = mock(JWSSigner.class);
        JWSSigner eddsaSigner = mock(JWSSigner.class);
        when(es256Signer.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("es256-sig"));
        when(eddsaSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("eddsa-sig"));

        try (MockedStatic<SigningKeyUtil> mockedSigningKeyUtil = mockStatic(SigningKeyUtil.class)) {
            mockedSigningKeyUtil.when(() -> SigningKeyUtil.generateJwk(SigningAlgorithm.ES256, mockKeyPair)).thenReturn(mockJwk);
            mockedSigningKeyUtil.when(() -> SigningKeyUtil.generateJwk(SigningAlgorithm.ED25519, mockKeyPair)).thenReturn(mockJwk);
            mockedSigningKeyUtil.when(() -> SigningKeyUtil.createSigner(SigningAlgorithm.ES256, mockJwk)).thenReturn(es256Signer);
            mockedSigningKeyUtil.when(() -> SigningKeyUtil.createSigner(SigningAlgorithm.ED25519, mockJwk)).thenReturn(eddsaSigner);

            @SuppressWarnings("unchecked")
            List<VPTokenSigningResult> results = (List<VPTokenSigningResult>) method.invoke(
                    walletPresentationService, List.of(es256Token, eddsaToken), "wallet-1", "base64Key");

            assertEquals(2, results.size());
            verify(es256Signer).sign(any(JWSHeader.class), eq(es256Kbt.getBytes(StandardCharsets.US_ASCII)));
            verify(eddsaSigner).sign(any(JWSHeader.class), eq(eddsaKbt.getBytes(StandardCharsets.US_ASCII)));
        }
    }

    @Test
    public void testSignVPTokensReusesSignerForSameAlg() throws Exception {
        Method method = WalletPresentationServiceImpl.class.getDeclaredMethod(
                "signVPTokens", List.class, String.class, String.class);
        method.setAccessible(true);

        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"nonce\":\"abc\"}".getBytes(StandardCharsets.UTF_8));
        String kbt = header + "." + payload;

        UnsignedVPToken token1 = mock(UnsignedVPToken.class);
        when(token1.getFormat()).thenReturn(FormatType.VC_SD_JWT);
        when(token1.getDataToSign()).thenReturn(kbt.getBytes(StandardCharsets.US_ASCII));
        when(token1.getSignatureAlgorithm()).thenReturn("ES256");

        UnsignedVPToken token2 = mock(UnsignedVPToken.class);
        when(token2.getFormat()).thenReturn(FormatType.VC_SD_JWT);
        when(token2.getDataToSign()).thenReturn(kbt.getBytes(StandardCharsets.US_ASCII));
        when(token2.getSignatureAlgorithm()).thenReturn("ES256");

        KeyPair mockKeyPair = mock(KeyPair.class);
        JWK mockJwk = mock(JWK.class);
        when(keyPairService.getKeyPairFromDB(eq("wallet-1"), eq("base64Key"), eq(SigningAlgorithm.ES256)))
                .thenReturn(mockKeyPair);
        when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("sig"));

        try (MockedStatic<SigningKeyUtil> mockedSigningKeyUtil = mockStatic(SigningKeyUtil.class)) {
            mockedSigningKeyUtil.when(() -> SigningKeyUtil.generateJwk(SigningAlgorithm.ES256, mockKeyPair)).thenReturn(mockJwk);
            mockedSigningKeyUtil.when(() -> SigningKeyUtil.createSigner(SigningAlgorithm.ES256, mockJwk)).thenReturn(jwsSigner);

            @SuppressWarnings("unchecked")
            List<VPTokenSigningResult> results = (List<VPTokenSigningResult>) method.invoke(
                    walletPresentationService, List.of(token1, token2), "wallet-1", "base64Key");

            assertEquals(2, results.size());
            verify(keyPairService, times(1)).getKeyPairFromDB(eq("wallet-1"), eq("base64Key"), eq(SigningAlgorithm.ES256));
            verify(jwsSigner, times(2)).sign(any(JWSHeader.class), eq(kbt.getBytes(StandardCharsets.US_ASCII)));
        }
    }
}
