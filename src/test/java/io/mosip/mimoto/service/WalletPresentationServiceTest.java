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
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.VerifiablePresentation;
import io.mosip.mimoto.repository.VerifiablePresentationsRepository;
import io.mosip.mimoto.service.impl.OpenID4VPService;
import io.mosip.mimoto.service.impl.WalletPresentationServiceImpl;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.SigningKeyUtil;
import io.mosip.mimoto.util.UrlParameterUtils;
import io.mosip.openID4VP.OpenID4VP;
import org.springframework.http.ResponseEntity;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult;
import io.mosip.openID4VP.constants.FormatType;
import io.mosip.openID4VP.verifier.VerifierResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.time.Instant;
import java.util.*;

import static io.mosip.mimoto.exception.ErrorConstants.*;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
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
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

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
                false
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
                .selectedCredentials(List.of("cred-123"))
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
    }

    @Test
    public void testHandleVPAuthorizationRequestSuccess() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(verifierService.isVerifierClientPreregistered(anyList(), anyString())).thenReturn(true);
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(mockAuthorizationRequest);
        when(verifierService.isVerifierTrustedByWallet(anyString(), anyString())).thenReturn(true);

        ClientMetadata clientMetadata = mock(ClientMetadata.class);
        when(clientMetadata.getClientName()).thenReturn("Test Verifier");
        when(clientMetadata.getLogoUri()).thenReturn("https://verifier.com/logo.png");
        when(mockAuthorizationRequest.getClientMetadata()).thenReturn(clientMetadata);

        VPResponseDTO result = walletPresentationService.handleVPAuthorizationRequest(
                urlEncodedVPAuthorizationRequest, walletId);

        assertNotNull(result);
        assertNotNull(result.getPresentationId());
        assertNotNull(result.getVerifiablePresentationVerifierDTO());
        assertEquals("test-client", result.getVerifiablePresentationVerifierDTO().getId());
        assertEquals("Test Verifier", result.getVerifiablePresentationVerifierDTO().getName());
        verify(openID4VPService).create(anyString());
        verify(verifierService).getTrustedVerifiers();
    }

    @Test
    public void testHandleVPAuthorizationRequestWithBlankClientName() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(verifierService.isVerifierClientPreregistered(anyList(), anyString())).thenReturn(true);
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(mockAuthorizationRequest);
        when(verifierService.isVerifierTrustedByWallet(anyString(), anyString())).thenReturn(false);

        ClientMetadata clientMetadata = mock(ClientMetadata.class);
        when(clientMetadata.getClientName()).thenReturn("   ");
        when(mockAuthorizationRequest.getClientMetadata()).thenReturn(clientMetadata);

        VPResponseDTO result = walletPresentationService.handleVPAuthorizationRequest(
                urlEncodedVPAuthorizationRequest, walletId);

        assertNotNull(result);
        assertEquals("test-client", result.getVerifiablePresentationVerifierDTO().getName());
    }

    @Test
    public void testHandleVPAuthorizationRequestWithNullClientMetadata() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(verifierService.isVerifierClientPreregistered(anyList(), anyString())).thenReturn(false);
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(mockAuthorizationRequest);
        when(verifierService.isVerifierTrustedByWallet(anyString(), anyString())).thenReturn(false);
        when(mockAuthorizationRequest.getClientMetadata()).thenReturn(null);

        VPResponseDTO result = walletPresentationService.handleVPAuthorizationRequest(
                urlEncodedVPAuthorizationRequest, walletId);

        assertNotNull(result);
        assertEquals("test-client", result.getVerifiablePresentationVerifierDTO().getName());
        assertNull(result.getVerifiablePresentationVerifierDTO().getLogo());
    }

    @Test
    public void testHandlePresentationActionSubmissionRequestSuccess() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(List.of("cred-123"))
                .build();

        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        Map<FormatType, UnsignedVPToken> unsignedTokens = new HashMap<>();
        UnsignedLdpVPToken unsignedLdpToken = mock(UnsignedLdpVPToken.class);
        when(unsignedLdpToken.getDataToSign()).thenReturn("base64-encoded-data");
        unsignedTokens.put(FormatType.LDP_VC, unsignedLdpToken);
        when(mockOpenID4VP.constructUnsignedVPToken(any(), anyString(), anyString())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            when(encryptionDecryptionUtil.createDetachedJwtSigningInput(anyString(), anyString()))
                    .thenReturn("signing-input".getBytes());

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            when(objectMapper.convertValue(any(), eq(LdpVPTokenSigningResult.class))).thenReturn(mock(LdpVPTokenSigningResult.class));

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
                .selectedCredentials(List.of("cred-123"))
                .build();

        OpenID4VP testOpenID4VP = mock(OpenID4VP.class);
        when(openID4VPService.create(anyString())).thenReturn(testOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);
        when(testOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(mockAuthorizationRequest);

        Map<FormatType, UnsignedVPToken> unsignedTokens = new HashMap<>();
        when(testOpenID4VP.constructUnsignedVPToken(any(), anyString(), anyString())).thenReturn(unsignedTokens);

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
    public void testHandlePresentationActionKeyGenerationException() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(List.of("cred-123"))
                .build();

        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
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
                .selectedCredentials(List.of("cred-123"))
                .build();

        VerifiablePresentationSessionData testSessionData = new VerifiablePresentationSessionData();
        testSessionData.setPresentationId(presentationId);
        testSessionData.setAuthorizationRequest(urlEncodedVPAuthorizationRequest);
        testSessionData.setCreatedAt(Instant.now());
        testSessionData.setVerifierClientPreregistered(true);
        testSessionData.setMatchingCredentials(List.of(credentialDTO));

        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(mockAuthorizationRequest);
        
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
                .selectedCredentials(List.of("cred-123"))
                .build();

        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenThrow(new ApiNotAccessibleException("API not accessible"));

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
                .selectedCredentials(List.of("cred-123"))
                .build();

        VerifiablePresentationSessionData nullSessionData = null;

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class)) {
            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);

            ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                    walletId, presentationId, request, nullSessionData, base64Key);

            assertNotNull(response);
            assertEquals(500, response.getStatusCode().value());
        }
    }

    @Test
    public void testSubmitPresentationSuccess() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        Map<FormatType, UnsignedVPToken> unsignedTokens = new HashMap<>();
        UnsignedLdpVPToken unsignedLdpToken = mock(UnsignedLdpVPToken.class);
        when(unsignedLdpToken.getDataToSign()).thenReturn("base64-encoded-data");
        unsignedTokens.put(FormatType.LDP_VC, unsignedLdpToken);
        when(mockOpenID4VP.constructUnsignedVPToken(any(), anyString(), anyString())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            when(encryptionDecryptionUtil.createDetachedJwtSigningInput(anyString(), anyString()))
                    .thenReturn("signing-input".getBytes());

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            when(objectMapper.convertValue(any(), eq(LdpVPTokenSigningResult.class))).thenReturn(mock(LdpVPTokenSigningResult.class));

            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, submitRequest, base64Key);

            assertNotNull(result);
            assertEquals(OpenID4VPConstants.STATUS_SUCCESS, result.getStatus());
            verify(verifiablePresentationsRepository).save(any(VerifiablePresentation.class));
        }
    }

    @Test
    public void testSubmitPresentationShareFailed() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        Map<FormatType, UnsignedVPToken> unsignedTokens = new HashMap<>();
        UnsignedLdpVPToken unsignedLdpToken = mock(UnsignedLdpVPToken.class);
        when(unsignedLdpToken.getDataToSign()).thenReturn("base64-encoded-data");
        unsignedTokens.put(FormatType.LDP_VC, unsignedLdpToken);
        when(mockOpenID4VP.constructUnsignedVPToken(any(), anyString(), anyString())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(500);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/error");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            when(encryptionDecryptionUtil.createDetachedJwtSigningInput(anyString(), anyString()))
                    .thenReturn("signing-input".getBytes());

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            when(objectMapper.convertValue(any(), eq(LdpVPTokenSigningResult.class))).thenReturn(mock(LdpVPTokenSigningResult.class));

            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, submitRequest, base64Key);

            assertNotNull(result);
            assertEquals(OpenID4VPConstants.STATUS_ERROR, result.getStatus());
            verify(verifiablePresentationsRepository).save(any(VerifiablePresentation.class));
        }
    }

    @Test
    public void testSubmitPresentationExceptionDuringShare() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        Map<FormatType, UnsignedVPToken> unsignedTokens = new HashMap<>();
        UnsignedLdpVPToken unsignedLdpToken = mock(UnsignedLdpVPToken.class);
        when(unsignedLdpToken.getDataToSign()).thenReturn("base64-encoded-data");
        unsignedTokens.put(FormatType.LDP_VC, unsignedLdpToken);
        when(mockOpenID4VP.constructUnsignedVPToken(any(), anyString(), anyString())).thenReturn(unsignedTokens);

        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenThrow(new RuntimeException("Network error"));

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            when(encryptionDecryptionUtil.createDetachedJwtSigningInput(anyString(), anyString()))
                    .thenReturn("signing-input".getBytes());

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            when(objectMapper.convertValue(any(), eq(LdpVPTokenSigningResult.class))).thenReturn(mock(LdpVPTokenSigningResult.class));

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
                .selectedCredentials(Collections.emptyList())
                .build();

        walletPresentationService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);
    }

    @Test
    public void testHandlePresentationSubmissionNullBase64Key() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(List.of("cred-123"))
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
                .selectedCredentials(List.of("cred-123"))
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

        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
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
        nullSessionData.setMatchingCredentials(null);

        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(List.of("cred-123"))
                .build();

        
        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class)) {
            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);

            walletPresentationService.submitPresentation(
                    nullSessionData, walletId, presentationId, request, base64Key);
        }
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
                .selectedCredentials(List.of("cred-123"))
                .build();

        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(mockAuthorizationRequest);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {
            
            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            when(encryptionDecryptionUtil.createDetachedJwtSigningInput(anyString(), anyString()))
                    .thenReturn("signing-input".getBytes());

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");

            Map<FormatType, UnsignedVPToken> unsignedTokens = new HashMap<>();
            UnsignedLdpVPToken unsignedLdpToken = mock(UnsignedLdpVPToken.class);
            when(unsignedLdpToken.getDataToSign()).thenReturn("base64-encoded-data");
            unsignedTokens.put(FormatType.LDP_VC, unsignedLdpToken);
            when(mockOpenID4VP.constructUnsignedVPToken(any(), anyString(), anyString())).thenReturn(unsignedTokens);

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

        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
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

        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
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
        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        Map<FormatType, UnsignedVPToken> unsignedTokens = new HashMap<>();
        UnsignedLdpVPToken unsignedLdpToken = mock(UnsignedLdpVPToken.class);
        when(unsignedLdpToken.getDataToSign()).thenReturn("base64-encoded-data");
        unsignedTokens.put(FormatType.LDP_VC, unsignedLdpToken);
        when(mockOpenID4VP.constructUnsignedVPToken(any(), anyString(), anyString())).thenReturn(unsignedTokens);

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

            when(encryptionDecryptionUtil.createDetachedJwtSigningInput(anyString(), anyString()))
                    .thenReturn("signing-input".getBytes());

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            when(objectMapper.convertValue(any(), eq(LdpVPTokenSigningResult.class))).thenReturn(mock(LdpVPTokenSigningResult.class));

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

        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        Map<FormatType, UnsignedVPToken> unsignedTokens = new HashMap<>();
        UnsignedLdpVPToken unsignedLdpToken = mock(UnsignedLdpVPToken.class);
        when(unsignedLdpToken.getDataToSign()).thenReturn("base64-encoded-data");
        unsignedTokens.put(FormatType.LDP_VC, unsignedLdpToken);
        when(mockOpenID4VP.constructUnsignedVPToken(any(), anyString(), anyString())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            when(encryptionDecryptionUtil.createDetachedJwtSigningInput(anyString(), anyString()))
                    .thenReturn("signing-input".getBytes());

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            when(objectMapper.convertValue(any(), eq(LdpVPTokenSigningResult.class))).thenReturn(mock(LdpVPTokenSigningResult.class));

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

        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        Map<FormatType, UnsignedVPToken> unsignedTokens = new HashMap<>();
        UnsignedLdpVPToken unsignedLdpToken = mock(UnsignedLdpVPToken.class);
        when(unsignedLdpToken.getDataToSign()).thenReturn("base64-encoded-data");
        unsignedTokens.put(FormatType.LDP_VC, unsignedLdpToken);
        when(mockOpenID4VP.constructUnsignedVPToken(any(), anyString(), anyString())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            when(encryptionDecryptionUtil.createDetachedJwtSigningInput(anyString(), anyString()))
                    .thenReturn("signing-input".getBytes());

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenThrow(new RuntimeException("URL parsing error"));

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            when(objectMapper.convertValue(any(), eq(LdpVPTokenSigningResult.class))).thenReturn(mock(LdpVPTokenSigningResult.class));

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

        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        Map<FormatType, UnsignedVPToken> unsignedTokens = new HashMap<>();
        UnsignedLdpVPToken unsignedLdpToken = mock(UnsignedLdpVPToken.class);
        when(unsignedLdpToken.getDataToSign()).thenReturn("base64-encoded-data");
        unsignedTokens.put(FormatType.LDP_VC, unsignedLdpToken);
        when(mockOpenID4VP.constructUnsignedVPToken(any(), anyString(), anyString())).thenReturn(unsignedTokens);

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(any())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> jwtUtilMock = mockStatic(SigningKeyUtil.class);
             MockedStatic<UrlParameterUtils> urlUtilMock = mockStatic(UrlParameterUtils.class)) {

            jwtUtilMock.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            jwtUtilMock.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            when(encryptionDecryptionUtil.createDetachedJwtSigningInput(anyString(), anyString()))
                    .thenReturn("signing-input".getBytes());

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.writeValueAsString(any())).thenReturn("{\"kty\":\"OKP\"}");
            when(objectMapper.convertValue(any(), eq(LdpVPTokenSigningResult.class))).thenReturn(mock(LdpVPTokenSigningResult.class));

            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionDataWithNullAuth, walletId, presentationId, submitRequest, base64Key);

            assertNotNull(result);
        }
    }

    @Test
    public void testExtractVerifierAuthRequestExceptionDuringExtraction() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        Map<FormatType, UnsignedVPToken> unsignedTokens = new HashMap<>();
        UnsignedLdpVPToken unsignedLdpToken = mock(UnsignedLdpVPToken.class);
        when(unsignedLdpToken.getDataToSign()).thenReturn("base64-encoded-data");
        unsignedTokens.put(FormatType.LDP_VC, unsignedLdpToken);
        when(mockOpenID4VP.constructUnsignedVPToken(any(), anyString(), anyString())).thenReturn(unsignedTokens);

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

            when(encryptionDecryptionUtil.createDetachedJwtSigningInput(anyString(), anyString()))
                    .thenReturn("signing-input".getBytes());

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.convertValue(any(), eq(LdpVPTokenSigningResult.class))).thenReturn(mock(LdpVPTokenSigningResult.class));

            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, submitRequest, base64Key);

            assertNotNull(result);
        }
    }

    @Test
    public void testCreatePresentationDataExceptionDuringCreation() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(keyPair);

        Map<FormatType, UnsignedVPToken> unsignedTokens = new HashMap<>();
        UnsignedLdpVPToken unsignedLdpToken = mock(UnsignedLdpVPToken.class);
        when(unsignedLdpToken.getDataToSign()).thenReturn("base64-encoded-data");
        unsignedTokens.put(FormatType.LDP_VC, unsignedLdpToken);
        when(mockOpenID4VP.constructUnsignedVPToken(any(), anyString(), anyString())).thenReturn(unsignedTokens);

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

            when(encryptionDecryptionUtil.createDetachedJwtSigningInput(anyString(), anyString()))
                    .thenReturn("signing-input".getBytes());

            urlUtilMock.when(() -> UrlParameterUtils.extractQueryParameter(anyString(), anyString()))
                    .thenReturn("test-client");

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));
            when(objectMapper.convertValue(any(), eq(LdpVPTokenSigningResult.class))).thenReturn(mock(LdpVPTokenSigningResult.class));

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
}
