package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.SigningKeyUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPair;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class V1CredentialRequestServiceTest {

    private static final String CREDENTIAL_CONFIG_ID = "config-1";
    private static final String NONCE_ENDPOINT = "https://example.com/nonce";
    private static final String CREDENTIAL_ISSUER = "https://example-issuer.com";
    @Mock
    private RestApiClient restApiClient;
    @Mock
    private KeyPairRetrievalService keyPairService;
    private V1CredentialRequestService service;
    private MockedStatic<SigningKeyUtil> signingKeyUtilMock;
    private IssuerDTO issuerDTO;
    private CredentialIssuerWellKnownResponse wellKnownResponse;
    private CredentialsSupportedResponse credentialsSupportedResponse;

    @BeforeEach
    void setUp() {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }

        service = new V1CredentialRequestService(restApiClient, keyPairService);
        ReflectionTestUtils.setField(service, "signingAlgorithmsPriorityOrder", "ED25519,ES256K,ES256,RS256");

        signingKeyUtilMock = Mockito.mockStatic(SigningKeyUtil.class, Mockito.withSettings().defaultAnswer(Mockito.CALLS_REAL_METHODS));

        issuerDTO = new IssuerDTO();
        issuerDTO.setIssuer_id("issuer-123");
        issuerDTO.setClient_id("client-123");

        ProofTypesSupported proofTypesSupported = new ProofTypesSupported();
        proofTypesSupported.setProofSigningAlgValuesSupported(List.of("Ed25519"));

        credentialsSupportedResponse = new CredentialsSupportedResponse();
        credentialsSupportedResponse.setFormat("vc+sd-jwt");
        credentialsSupportedResponse.setProofTypesSupported(new HashMap<>(Map.of("jwt", proofTypesSupported)));

        wellKnownResponse = new CredentialIssuerWellKnownResponse();
        wellKnownResponse.setCredentialIssuer(CREDENTIAL_ISSUER);
        wellKnownResponse.setNonceEndpoint(NONCE_ENDPOINT);
        wellKnownResponse.setCredentialConfigurationsSupported(Map.of(CREDENTIAL_CONFIG_ID, credentialsSupportedResponse));
    }

    @AfterEach
    void tearDown() {
        if (signingKeyUtilMock != null) {
            signingKeyUtilMock.close();
        }
    }

    @Test
    void shouldBuildRequestWithNonceWhenNonceEndpointIsPresent() throws Exception {
        NonceResponse nonceResponse = new NonceResponse("test-nonce");
        when(restApiClient.postApi(eq(NONCE_ENDPOINT), eq(MediaType.APPLICATION_JSON), isNull(), eq(NonceResponse.class))).thenReturn(nonceResponse);

        V1VCCredentialRequest result = service.buildRequest(issuerDTO, CREDENTIAL_CONFIG_ID, wellKnownResponse, null, null, false);

        assertNotNull(result);
        assertEquals(CREDENTIAL_CONFIG_ID, result.getCredentialConfigurationId());
        assertNotNull(result.getProofs());
        assertTrue(result.getProofs().containsKey("jwt"));
        assertEquals(1, result.getProofs().get("jwt").size());

        ArgumentCaptor<String> nonceCaptor = ArgumentCaptor.forClass(String.class);
        signingKeyUtilMock.verify(() -> SigningKeyUtil.generateJwt(any(SigningAlgorithm.class), eq(CREDENTIAL_ISSUER), eq("client-123"), nonceCaptor.capture(), any(KeyPair.class)));
        assertEquals("test-nonce", nonceCaptor.getValue());
    }

    @Test
    void shouldBuildRequestWithoutNonceWhenNonceEndpointIsAbsent() throws Exception {
        wellKnownResponse.setNonceEndpoint(null);

        V1VCCredentialRequest result = service.buildRequest(issuerDTO, CREDENTIAL_CONFIG_ID, wellKnownResponse, null, null, false);

        assertNotNull(result);
        assertEquals(CREDENTIAL_CONFIG_ID, result.getCredentialConfigurationId());
        assertNotNull(result.getProofs());

        ArgumentCaptor<String> nonceCaptor = ArgumentCaptor.forClass(String.class);
        signingKeyUtilMock.verify(() -> SigningKeyUtil.generateJwt(any(SigningAlgorithm.class), eq(CREDENTIAL_ISSUER), eq("client-123"), nonceCaptor.capture(), any(KeyPair.class)));
        assertNull(nonceCaptor.getValue());
    }

    @Test
    void shouldBuildRequestWithoutNonceWhenNonceEndpointIsBlank() throws Exception {
        wellKnownResponse.setNonceEndpoint("  ");

        V1VCCredentialRequest result = service.buildRequest(issuerDTO, CREDENTIAL_CONFIG_ID, wellKnownResponse, null, null, false);

        assertNotNull(result);

        ArgumentCaptor<String> nonceCaptor = ArgumentCaptor.forClass(String.class);
        signingKeyUtilMock.verify(() -> SigningKeyUtil.generateJwt(any(SigningAlgorithm.class), eq(CREDENTIAL_ISSUER), eq("client-123"), nonceCaptor.capture(), any(KeyPair.class)));
        assertNull(nonceCaptor.getValue());
    }

    @Test
    void shouldBuildRequestWithoutNonceWhenNonceEndpointReturnsNull() throws Exception {
        when(restApiClient.postApi(eq(NONCE_ENDPOINT), eq(MediaType.APPLICATION_JSON), isNull(), eq(NonceResponse.class))).thenReturn(null);

        V1VCCredentialRequest result = service.buildRequest(issuerDTO, CREDENTIAL_CONFIG_ID, wellKnownResponse, null, null, false);

        assertNotNull(result);

        ArgumentCaptor<String> nonceCaptor = ArgumentCaptor.forClass(String.class);
        signingKeyUtilMock.verify(() -> SigningKeyUtil.generateJwt(any(SigningAlgorithm.class), eq(CREDENTIAL_ISSUER), eq("client-123"), nonceCaptor.capture(), any(KeyPair.class)));
        assertNull(nonceCaptor.getValue());
    }

    @Test
    void shouldBuildRequestWithoutNonceWhenNonceResponseHasNullCNonce() throws Exception {
        NonceResponse nonceResponse = new NonceResponse(null);
        when(restApiClient.postApi(eq(NONCE_ENDPOINT), eq(MediaType.APPLICATION_JSON), isNull(), eq(NonceResponse.class))).thenReturn(nonceResponse);

        V1VCCredentialRequest result = service.buildRequest(issuerDTO, CREDENTIAL_CONFIG_ID, wellKnownResponse, null, null, false);

        assertNotNull(result);

        ArgumentCaptor<String> nonceCaptor = ArgumentCaptor.forClass(String.class);
        signingKeyUtilMock.verify(() -> SigningKeyUtil.generateJwt(any(SigningAlgorithm.class), eq(CREDENTIAL_ISSUER), eq("client-123"), nonceCaptor.capture(), any(KeyPair.class)));
        assertNull(nonceCaptor.getValue());
    }

    @Test
    void shouldUseDBKeysForLoginFlow() throws Exception {
        NonceResponse nonceResponse = new NonceResponse("test-nonce");
        when(restApiClient.postApi(eq(NONCE_ENDPOINT), eq(MediaType.APPLICATION_JSON), isNull(), eq(NonceResponse.class))).thenReturn(nonceResponse);

        KeyPair mockKeyPair = Mockito.mock(KeyPair.class);

        when(keyPairService.getKeyPairFromDB("wallet-1", "key-base64", SigningAlgorithm.ED25519)).thenReturn(mockKeyPair);

        signingKeyUtilMock.when(() -> SigningKeyUtil.generateJwt(eq(SigningAlgorithm.ED25519), eq(CREDENTIAL_ISSUER), eq("client-123"), eq("test-nonce"), eq(mockKeyPair))).thenReturn("mocked-jwt-token");

        V1VCCredentialRequest result = service.buildRequest(issuerDTO, CREDENTIAL_CONFIG_ID, wellKnownResponse, "wallet-1", "key-base64", true);

        assertNotNull(result);
        assertEquals(CREDENTIAL_CONFIG_ID, result.getCredentialConfigurationId());
        assertEquals(List.of("mocked-jwt-token"), result.getProofs().get("jwt"));
        signingKeyUtilMock.verify(() -> SigningKeyUtil.generateJwt(eq(SigningAlgorithm.ED25519), eq(CREDENTIAL_ISSUER), eq("client-123"), eq("test-nonce"), eq(mockKeyPair)));
    }

    @Test
    void shouldUseFallbackAlgorithmWhenJwtProofTypeIsNull() throws Exception {
        credentialsSupportedResponse.getProofTypesSupported().put("jwt", null);

        NonceResponse nonceResponse = new NonceResponse("test-nonce");
        when(restApiClient.postApi(eq(NONCE_ENDPOINT), eq(MediaType.APPLICATION_JSON), isNull(), eq(NonceResponse.class))).thenReturn(nonceResponse);

        V1VCCredentialRequest result = service.buildRequest(issuerDTO, CREDENTIAL_CONFIG_ID, wellKnownResponse, null, null, false);

        assertNotNull(result);

        ArgumentCaptor<SigningAlgorithm> algCaptor = ArgumentCaptor.forClass(SigningAlgorithm.class);
        signingKeyUtilMock.verify(() -> SigningKeyUtil.generateKeyPair(algCaptor.capture()));
        assertEquals(SigningAlgorithm.ED25519, algCaptor.getValue());
    }

    @Test
    void shouldUseFallbackAlgorithmWhenProofAlgorithmsAreEmpty() throws Exception {
        ProofTypesSupported emptyProof = new ProofTypesSupported();
        emptyProof.setProofSigningAlgValuesSupported(Collections.emptyList());
        credentialsSupportedResponse.getProofTypesSupported().put("jwt", emptyProof);

        NonceResponse nonceResponse = new NonceResponse("test-nonce");
        when(restApiClient.postApi(eq(NONCE_ENDPOINT), eq(MediaType.APPLICATION_JSON), isNull(), eq(NonceResponse.class))).thenReturn(nonceResponse);

        V1VCCredentialRequest result = service.buildRequest(issuerDTO, CREDENTIAL_CONFIG_ID, wellKnownResponse, null, null, false);

        assertNotNull(result);

        ArgumentCaptor<SigningAlgorithm> algCaptor = ArgumentCaptor.forClass(SigningAlgorithm.class);
        signingKeyUtilMock.verify(() -> SigningKeyUtil.generateKeyPair(algCaptor.capture()));
        assertEquals(SigningAlgorithm.ED25519, algCaptor.getValue());
    }

    @Test
    void shouldUseHighestPriorityMatchingAlgorithm() throws Exception {
        credentialsSupportedResponse.getProofTypesSupported().get("jwt").setProofSigningAlgValuesSupported(List.of("ES256K"));

        NonceResponse nonceResponse = new NonceResponse("test-nonce");
        when(restApiClient.postApi(eq(NONCE_ENDPOINT), eq(MediaType.APPLICATION_JSON), isNull(), eq(NonceResponse.class))).thenReturn(nonceResponse);

        V1VCCredentialRequest result = service.buildRequest(issuerDTO, CREDENTIAL_CONFIG_ID, wellKnownResponse, null, null, false);

        assertNotNull(result);

        ArgumentCaptor<SigningAlgorithm> algCaptor = ArgumentCaptor.forClass(SigningAlgorithm.class);
        signingKeyUtilMock.verify(() -> SigningKeyUtil.generateKeyPair(algCaptor.capture()));
        assertEquals(SigningAlgorithm.ES256K, algCaptor.getValue());
    }

    @Test
    void shouldReturnCorrectSigningAlgorithmsPriorityOrder() {
        assertEquals(4, service.getSigningAlgorithmsPriorityOrder().size());
        assertTrue(service.getSigningAlgorithmsPriorityOrder().contains("ED25519"));
    }
}
