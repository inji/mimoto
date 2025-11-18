package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.VerifiablePresentationResponseDTO;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponseProof;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.openid.presentation.FieldDTO;
import io.mosip.mimoto.dto.openid.presentation.InputDescriptorDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.VPErrorNotSentException;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.impl.DataShareServiceImpl;
import io.mosip.mimoto.service.impl.OpenID4VPService;
import io.mosip.mimoto.service.impl.PresentationServiceImpl;
import io.mosip.mimoto.util.JwtUtils;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.verifier.VerifierResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;
import io.mosip.mimoto.dto.SubmitPresentationResponseDTO;

import java.io.IOException;
import java.time.Instant;
import java.util.*;

import static io.mosip.mimoto.exception.ErrorConstants.REJECTED_VERIFIER;
import static io.mosip.mimoto.util.JwtUtils.parseJwtHeader;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static io.mosip.mimoto.util.TestUtilities.*;

@RunWith(MockitoJUnitRunner.class)
public class PresentationServiceTest {
    @Mock
    VerifierService verifierService;
    @Mock
    DataShareServiceImpl dataShareService;

    @Mock
    ObjectMapper objectMapper;

    @Mock
    private OpenID4VPService openID4VPService;

    @Mock
    RestApiClient restApiClient;

    @InjectMocks
    PresentationServiceImpl presentationService;

    String walletId, clientId, urlEncodedVPAuthorizationRequest;
    VerifiersDTO verifiersDTO;
    VerifierDTO verifierDTO;
    List<Verifier> preRegisteredVerifiers;
    UUID fixedUuid;
    Instant fixedInstant;

    @Before
    public void setup() throws JsonProcessingException {
        ReflectionTestUtils.setField(presentationService, "injiOvpRedirectURLPattern", "%s#vp_token=%s&presentation_submission=%s");
        ReflectionTestUtils.setField(presentationService, "maximumResponseHeaderSize", 65536);
        when(objectMapper.writeValueAsString(any())).thenReturn("test-data");

        // Setup for Wallet presentation tests
        walletId = "wallet-123";
        clientId = "test-clientId";
        urlEncodedVPAuthorizationRequest =
                "client_id=test-clientId&presentation_definition_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fpresentation_definition_uri&response_type=vp_token&response_mode=direct_post&nonce=NHgLcWlae745DpfJbUyfdg%253D%253D&response_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response&state=pcmxBfvdPEcjFObgt%252BLekA%253D%253D";

        verifierDTO = new VerifierDTO(
                clientId,
                List.of("redirect-uri"),
                List.of("https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response"),
                null,
                false
        );
        verifiersDTO = new VerifiersDTO();
        verifiersDTO.setVerifiers(List.of(verifierDTO));
        preRegisteredVerifiers = List.of(
                new Verifier(verifierDTO.getClientId(), verifierDTO.getResponseUris(), null)
        );

        fixedUuid = UUID.fromString("123e4567-e89b-12d3-a456-426614174000");
        fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
    }

    @Test
    public void credentialProofMatchingWithVPRequest() throws Exception {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn((VCCredentialProperties) vcCredentialResponse.getCredential());
        String expectedRedirectUrl = "test_redirect_uri#vp_token=dGVzdC1kYXRh&presentation_submission=test-data";

        String actualRedirectUrl = presentationService.authorizePresentation(TestUtilities.getPresentationRequestDTO());

        assertEquals(expectedRedirectUrl, actualRedirectUrl);
    }

    @Test(expected = VPNotCreatedException.class)
    public void credentialProofMismatchWithVPRequest() throws IOException {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("RSASignature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn((VCCredentialProperties) vcCredentialResponse.getCredential());
        presentationService.authorizePresentation(TestUtilities.getPresentationRequestDTO());
    }

    @Test
    public void sdJwtCredentialMatchingWithVPRequest() throws Exception {
        VCCredentialResponse vcCredentialResponse = createSDJwtCredentialResponse("vc+sd-jwt");
        PresentationRequestDTO presentationRequestDTO = createSDJwtPresentationRequest();
        Map<String, Object> jwtHeaders = Map.of("alg", "ES256", "typ", "JWT");

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(String.class)))
                .thenReturn("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.test.signature");

        try (MockedStatic<JwtUtils> jwtUtilsMock = mockStatic(JwtUtils.class)) {
            jwtUtilsMock.when(() -> parseJwtHeader(anyString())).thenReturn(jwtHeaders);

            String expectedRedirectUrl = "test_redirect_uri#vp_token=dGVzdC1kYXRh&presentation_submission=test-data";
            String actualRedirectUrl = presentationService.authorizePresentation(presentationRequestDTO);

            assertEquals(expectedRedirectUrl, actualRedirectUrl);
        }
    }

    @Test(expected = VPNotCreatedException.class)
    public void nullPresentationDefinitionWithVPRequest() throws IOException {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        presentationRequestDTO.setPresentationDefinition(null);

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);

        presentationService.authorizePresentation(presentationRequestDTO);
    }

    @Test(expected = VPNotCreatedException.class)
    public void uriTooLongWithVPRequest() throws IOException {
        ReflectionTestUtils.setField(presentationService, "maximumResponseHeaderSize", 10); // Very small limit

        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn((VCCredentialProperties) vcCredentialResponse.getCredential());
        when(objectMapper.writeValueAsString(any())).thenReturn("very-long-test-data-that-exceeds-limit");

        presentationService.authorizePresentation(presentationRequestDTO);
    }

    @Test
    public void constructPresentationDefinitionForLdpVcCredential() {
        VCCredentialResponse vcCredentialResponse = createLdpVcCredentialResponse();
        VCCredentialProperties credential = (VCCredentialProperties) vcCredentialResponse.getCredential();
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn(credential);

        PresentationDefinitionDTO result = presentationService.constructPresentationDefinition(vcCredentialResponse);

        assertNotNull(result);
        assertNotNull(result.getId());
        assertEquals(1, result.getInputDescriptors().size());

        InputDescriptorDTO inputDescriptor = result.getInputDescriptors().get(0);
        assertNotNull(inputDescriptor.getId());
        assertTrue(inputDescriptor.getFormat().containsKey("ldpVc"));
        assertTrue(inputDescriptor.getFormat().get("ldpVc").containsKey("proofTypes"));
    }

    @Test
    public void constructPresentationDefinitionForSdJwtCredential() {
        VCCredentialResponse vcCredentialResponse = createSDJwtCredentialResponse("vc+sd-jwt");
        Map<String, Object> jwtPayload = Map.of("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        Map<String, Object> jwtHeaders = Map.of("alg", "ES256", "typ", "JWT");

        try (MockedStatic<JwtUtils> jwtUtilsMock = mockStatic(JwtUtils.class)) {
            jwtUtilsMock.when(() -> JwtUtils.extractJwtPayloadFromSdJwt(anyString())).thenReturn(jwtPayload);
            jwtUtilsMock.when(() -> JwtUtils.parseJwtHeader(anyString())).thenReturn(jwtHeaders);

            PresentationDefinitionDTO result = presentationService.constructPresentationDefinition(vcCredentialResponse);

            assertNotNull(result);
            assertEquals(1, result.getInputDescriptors().size());
            assertTrue(result.getInputDescriptors().get(0).getFormat().containsKey("vc+sd-jwt"));
        }
    }

    @Test
    public void testHandleVPAuthorizationRequest_successful() throws Exception {
        try (MockedStatic<UUID> mockedStatic = mockStatic(UUID.class);
             MockedStatic<Instant> mockedInstant = mockStatic(Instant.class)) {

            mockedStatic.when(UUID::randomUUID).thenReturn(fixedUuid);
            mockedInstant.when(Instant::now).thenReturn(fixedInstant);

            when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
            when(verifierService.isVerifierTrustedByWallet(clientId, walletId)).thenReturn(true);

            OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
            when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
            when(mockOpenID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest, preRegisteredVerifiers, false))
                    .thenReturn(getPresentationAuthorizationRequest(clientId, "https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response"));

            VerifiablePresentationResponseDTO expectedPresentationResponseDTO = getVerifiablePresentationResponseDTO("test-clientId", "test-clientId", null, true, true, "https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response", mockOpenID4VP, fixedInstant);

            VerifiablePresentationResponseDTO actualPresentationResponseDTO =
                    presentationService.handleVPAuthorizationRequest(urlEncodedVPAuthorizationRequest, walletId);

            assertEquals(expectedPresentationResponseDTO, actualPresentationResponseDTO);
        }
    }

    @Test
    public void testHandleVPAuthorizationRequest_untrustedVerifier() throws Exception {
        try (MockedStatic<UUID> mockedStatic = mockStatic(UUID.class);
             MockedStatic<Instant> mockedInstant = mockStatic(Instant.class)) {

            mockedStatic.when(UUID::randomUUID).thenReturn(fixedUuid);
            mockedInstant.when(Instant::now).thenReturn(fixedInstant);

            when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
            when(verifierService.isVerifierTrustedByWallet(clientId, walletId)).thenReturn(false);

            OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
            when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
            when(mockOpenID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest, preRegisteredVerifiers, false))
                    .thenReturn(getPresentationAuthorizationRequest(clientId, "https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response"));

            VerifiablePresentationResponseDTO expectedPresentationResponseDTO = getVerifiablePresentationResponseDTO("test-clientId", "test-clientId", null, false, true, "https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response", mockOpenID4VP, fixedInstant);

            VerifiablePresentationResponseDTO actualPresentationResponseDTO =
                    presentationService.handleVPAuthorizationRequest(urlEncodedVPAuthorizationRequest, walletId);

            assertEquals(expectedPresentationResponseDTO, actualPresentationResponseDTO);
        }
    }

    @Test
    public void testHandleVPAuthorizationRequest_verifierNotPreRegisteredWithWallet() throws Exception {
        clientId = "unknown-clientId";
        try (MockedStatic<UUID> mockedStatic = mockStatic(UUID.class);
             MockedStatic<Instant> mockedInstant = mockStatic(Instant.class)) {

            mockedStatic.when(UUID::randomUUID).thenReturn(fixedUuid);
            mockedInstant.when(Instant::now).thenReturn(fixedInstant);

            when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
            when(verifierService.isVerifierTrustedByWallet(clientId, walletId)).thenReturn(false);

            OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
            when(openID4VPService.create(anyString())).thenReturn(mockOpenID4VP);
            when(mockOpenID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest, preRegisteredVerifiers, false))
                    .thenReturn(getPresentationAuthorizationRequest(clientId, "https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response"));

            VerifiablePresentationResponseDTO expectedPresentationResponseDTO = getVerifiablePresentationResponseDTO("unknown-clientId", "unknown-clientId", null, false, false, "https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response", mockOpenID4VP, fixedInstant);

            VerifiablePresentationResponseDTO actualPresentationResponseDTO =
                    presentationService.handleVPAuthorizationRequest(urlEncodedVPAuthorizationRequest, walletId);

            assertEquals(expectedPresentationResponseDTO, actualPresentationResponseDTO);
        }
    }

    // Helper methods
    private VCCredentialResponse createSDJwtCredentialResponse(String format) {
        VCCredentialResponse response = new VCCredentialResponse();
        response.setFormat(format);
        response.setCredential("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.test.signature");
        return response;
    }

    private PresentationRequestDTO createSDJwtPresentationRequest() {
        PresentationRequestDTO request = new PresentationRequestDTO();
        request.setRedirectUri("test_redirect_uri");

        Map<String, Map<String, List<String>>> format = Map.of(
                "vc+sd-jwt", Map.of("sd-jwt_alg_values", Arrays.asList("ES256"))
        );

        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder()
                .id("test-id")
                .format(format)
                .build();

        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder()
                .id("test-presentation-def")
                .inputDescriptors(Arrays.asList(inputDescriptor))
                .build();

        request.setPresentationDefinition(presentationDefinition);
        return request;
    }

    private VCCredentialResponse createLdpVcCredentialResponse() {
        VCCredentialResponse response = new VCCredentialResponse();
        response.setFormat(CredentialFormat.LDP_VC.getFormat());

        VCCredentialProperties credential = new VCCredentialProperties();
        credential.setType(Arrays.asList("VerifiableCredential", "TestCredential"));
        credential.setContext("https://www.w3.org/2018/credentials/v1");

        VCCredentialResponseProof proof = new VCCredentialResponseProof();
        proof.setType("Ed25519Signature2020");
        credential.setProof(proof);

        response.setCredential(credential);
        return response;
    }

    @Test(expected = RuntimeException.class)
    public void authorizePresentationNullCredentialThrowsException() throws Exception {
        VCCredentialResponse vcCredentialResponse = new VCCredentialResponse();
        vcCredentialResponse.setCredential(null);
        vcCredentialResponse.setFormat(CredentialFormat.LDP_VC.getFormat());

        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(null), eq(VCCredentialProperties.class))).thenReturn(null);

        presentationService.authorizePresentation(presentationRequestDTO);
    }

    @Test(expected = VPNotCreatedException.class)
    public void authorizePresentationUnsupportedCredentialFormatThrowsException() throws Exception {
        VCCredentialResponse vcCredentialResponse = new VCCredentialResponse();
        vcCredentialResponse.setCredential("dummy");
        vcCredentialResponse.setFormat("unsupported-format");

        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);

        presentationService.authorizePresentation(presentationRequestDTO);
    }

    @Test(expected = RuntimeException.class)
    public void authorizePresentationObjectMapperThrowsException() throws Exception {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenThrow(new RuntimeException("Mapping error"));
        presentationService.authorizePresentation(presentationRequestDTO);
    }

    @Test(expected = NullPointerException.class)
    public void constructPresentationDefinitionNullCredentialCausesNPE() {
        VCCredentialResponse vcCredentialResponse = new VCCredentialResponse();
        vcCredentialResponse.setCredential(null);
        vcCredentialResponse.setFormat(CredentialFormat.LDP_VC.getFormat());

        when(objectMapper.convertValue(eq(null), eq(VCCredentialProperties.class))).thenReturn(null);

        presentationService.constructPresentationDefinition(vcCredentialResponse);
    }

    // Test for constructPresentationDefinition with proper null handling
    @Test
    public void constructPresentationDefinitionWithValidCredential() {
        VCCredentialResponse vcCredentialResponse = createLdpVcCredentialResponse();
        VCCredentialProperties credential = (VCCredentialProperties) vcCredentialResponse.getCredential();
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn(credential);

        PresentationDefinitionDTO result = presentationService.constructPresentationDefinition(vcCredentialResponse);

        assertNotNull(result);
        assertNotNull(result.getId());
        assertEquals(1, result.getInputDescriptors().size());
    }

    @Test
    public void constructPresentationDefinitionUnsupportedFormatReturnsNull() {
        VCCredentialResponse vcCredentialResponse = new VCCredentialResponse();
        vcCredentialResponse.setCredential("dummy");
        vcCredentialResponse.setFormat("unsupported-format");

        PresentationDefinitionDTO result = presentationService.constructPresentationDefinition(vcCredentialResponse);

        assertNotNull(result);
        assertTrue(result.getInputDescriptors().isEmpty());
    }

    @Test
    public void testDirectPostResponseMode() throws Exception {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        presentationRequestDTO.setResponseMode("direct_post");
        presentationRequestDTO.setResponseUri("https://verifier.example.com/response");
        presentationRequestDTO.setState("test-state");
        presentationRequestDTO.setNonce("test-nonce");

        Map<String, Object> mockResponse = Map.of("redirect_uri", "https://verifier.example.com/success");

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn((VCCredentialProperties) vcCredentialResponse.getCredential());
        when(restApiClient.postApi(anyString(), any(), any(), eq(Map.class))).thenReturn(mockResponse);

        String result = presentationService.authorizePresentation(presentationRequestDTO);

        assertEquals("test_redirect_uri", result);
        verify(restApiClient).postApi(eq("https://verifier.example.com/response"), any(), any(), eq(Map.class));
    }

    @Test
    public void testDirectPostResponseModeWithNoRedirectURIParam() throws Exception {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        presentationRequestDTO.setResponseMode("direct_post");
        presentationRequestDTO.setResponseUri("https://verifier.example.com/response");
        presentationRequestDTO.setState("test-state");
        presentationRequestDTO.setNonce("test-nonce");
        presentationRequestDTO.setRedirectUri("");

        Map<String, Object> mockResponse = Map.of("redirect_uri", "https://verifier.example.com/success");

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn((VCCredentialProperties) vcCredentialResponse.getCredential());
        when(restApiClient.postApi(anyString(), any(), any(), eq(Map.class))).thenReturn(mockResponse);

        String result = presentationService.authorizePresentation(presentationRequestDTO);

        assertEquals("https://verifier.example.com/success", result);
        verify(restApiClient).postApi(eq("https://verifier.example.com/response"), any(), any(), eq(Map.class));
    }

    @Test(expected = VPNotCreatedException.class)
    public void testSdJwtUnsupportedAlgorithm() throws Exception {
        VCCredentialResponse vcCredentialResponse = createSDJwtCredentialResponse("vc+sd-jwt");
        PresentationRequestDTO presentationRequestDTO = createSDJwtPresentationRequest();
        Map<String, Object> jwtHeaders = Map.of("alg", "RS256", "typ", "JWT"); // Unsupported algorithm

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(String.class)))
                .thenReturn("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test.signature");

        try (MockedStatic<JwtUtils> jwtUtilsMock = mockStatic(JwtUtils.class)) {
            jwtUtilsMock.when(() -> parseJwtHeader(anyString())).thenReturn(jwtHeaders);

            presentationService.authorizePresentation(presentationRequestDTO);
        }
    }

    @Test(expected = VPNotCreatedException.class)
    public void testMissingInputDescriptors() throws Exception {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();

        // Set empty input descriptors list
        PresentationDefinitionDTO presentationDefinition = presentationRequestDTO.getPresentationDefinition();
        presentationDefinition.setInputDescriptors(Arrays.asList());

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);

        presentationService.authorizePresentation(presentationRequestDTO);
    }

    @Test
    public void testDirectPostResponseModeWithoutRedirectUri() throws Exception {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        presentationRequestDTO.setResponseMode("direct_post");
        presentationRequestDTO.setResponseUri("https://verifier.example.com/response");
        presentationRequestDTO.setState("test-state");
        presentationRequestDTO.setNonce("test-nonce");

        // Mock response without redirect_uri
        Map<String, Object> mockResponse = Map.of("status", "success");

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn((VCCredentialProperties) vcCredentialResponse.getCredential());
        when(restApiClient.postApi(anyString(), any(), any(), eq(Map.class))).thenReturn(mockResponse);

        String result = presentationService.authorizePresentation(presentationRequestDTO);

        assertEquals("test_redirect_uri", result);
        verify(restApiClient).postApi(eq("https://verifier.example.com/response"), any(), any(), eq(Map.class));
    }

    @Test(expected = VPNotCreatedException.class)
    public void testDirectPostResponseModeWithException() throws Exception {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        presentationRequestDTO.setResponseMode("direct_post");
        presentationRequestDTO.setResponseUri("https://verifier.example.com/response");
        presentationRequestDTO.setState("test-state");
        presentationRequestDTO.setNonce("test-nonce");

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn((VCCredentialProperties) vcCredentialResponse.getCredential());
        when(restApiClient.postApi(anyString(), any(), any(), eq(Map.class)))
                .thenThrow(new RuntimeException("Network error"));

        presentationService.authorizePresentation(presentationRequestDTO);
    }

    @Test
    public void testConstructPresentationDefinitionForSdJwtWithMapType() {
        VCCredentialResponse vcCredentialResponse = createSDJwtCredentialResponse("dc+sd-jwt");

        // Create complex type structure with Map containing _value
        Map<String, Object> typeMap = new HashMap<>();
        typeMap.put("_value", "TestCredential");

        Map<String, Object> jwtPayload = Map.of("type", Arrays.asList("VerifiableCredential", typeMap));
        Map<String, Object> jwtHeaders = Map.of("alg", "ES256", "typ", "JWT");

        try (MockedStatic<JwtUtils> jwtUtilsMock = mockStatic(JwtUtils.class)) {
            jwtUtilsMock.when(() -> JwtUtils.extractJwtPayloadFromSdJwt(anyString())).thenReturn(jwtPayload);
            jwtUtilsMock.when(() -> JwtUtils.parseJwtHeader(anyString())).thenReturn(jwtHeaders);

            PresentationDefinitionDTO result = presentationService.constructPresentationDefinition(vcCredentialResponse);

            assertNotNull(result);
            assertEquals(1, result.getInputDescriptors().size());
            assertTrue(result.getInputDescriptors().get(0).getFormat().containsKey("dc+sd-jwt"));

            // Verify the filter pattern is set to the extracted type
            InputDescriptorDTO inputDescriptor = result.getInputDescriptors().get(0);
            FieldDTO field = inputDescriptor.getConstraints().getFields()[0];
            assertEquals("TestCredential", field.getFilter().getPattern());
        }
    }

    @Test
    public void testConstructPresentationDefinitionForSdJwtWithStringType() {
        VCCredentialResponse vcCredentialResponse = createSDJwtCredentialResponse("vc+sd-jwt");

        // Create simple type structure with String
        Map<String, Object> jwtPayload = Map.of("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        Map<String, Object> jwtHeaders = Map.of("alg", "ES256", "typ", "JWT");

        try (MockedStatic<JwtUtils> jwtUtilsMock = mockStatic(JwtUtils.class)) {
            jwtUtilsMock.when(() -> JwtUtils.extractJwtPayloadFromSdJwt(anyString())).thenReturn(jwtPayload);
            jwtUtilsMock.when(() -> JwtUtils.parseJwtHeader(anyString())).thenReturn(jwtHeaders);

            PresentationDefinitionDTO result = presentationService.constructPresentationDefinition(vcCredentialResponse);

            assertNotNull(result);
            assertEquals(1, result.getInputDescriptors().size());
            assertTrue(result.getInputDescriptors().get(0).getFormat().containsKey("vc+sd-jwt"));

            // Verify the filter pattern is set to the extracted type
            InputDescriptorDTO inputDescriptor = result.getInputDescriptors().get(0);
            FieldDTO field = inputDescriptor.getConstraints().getFields()[0];
            assertEquals("TestCredential", field.getFilter().getPattern());
        }
    }

    @Test
    public void testConstructPresentationDefinitionForSdJwtWithNullType() {
        VCCredentialResponse vcCredentialResponse = createSDJwtCredentialResponse("vc+sd-jwt");

        // Create payload with null type using HashMap to allow null values
        Map<String, Object> jwtPayload = new HashMap<>();
        jwtPayload.put("type", null);
        Map<String, Object> jwtHeaders = Map.of("alg", "ES256", "typ", "JWT");

        try (MockedStatic<JwtUtils> jwtUtilsMock = mockStatic(JwtUtils.class)) {
            jwtUtilsMock.when(() -> JwtUtils.extractJwtPayloadFromSdJwt(anyString())).thenReturn(jwtPayload);
            jwtUtilsMock.when(() -> JwtUtils.parseJwtHeader(anyString())).thenReturn(jwtHeaders);

            PresentationDefinitionDTO result = presentationService.constructPresentationDefinition(vcCredentialResponse);

            assertNotNull(result);
            assertEquals(1, result.getInputDescriptors().size());
            assertTrue(result.getInputDescriptors().get(0).getFormat().containsKey("vc+sd-jwt"));

            // Verify the filter pattern is null when type is null
            InputDescriptorDTO inputDescriptor = result.getInputDescriptors().get(0);
            FieldDTO field = inputDescriptor.getConstraints().getFields()[0];
            assertNull(field.getFilter().getPattern());
        }
    }

    @Test
    public void testConstructPresentationDefinitionForSdJwtWithEmptyTypeList() {
        VCCredentialResponse vcCredentialResponse = createSDJwtCredentialResponse("dc+sd-jwt");

        // Create payload with empty type list
        Map<String, Object> jwtPayload = Map.of("type", Arrays.asList());
        Map<String, Object> jwtHeaders = Map.of("alg", "ES256", "typ", "JWT");

        try (MockedStatic<JwtUtils> jwtUtilsMock = mockStatic(JwtUtils.class)) {
            jwtUtilsMock.when(() -> JwtUtils.extractJwtPayloadFromSdJwt(anyString())).thenReturn(jwtPayload);
            jwtUtilsMock.when(() -> JwtUtils.parseJwtHeader(anyString())).thenReturn(jwtHeaders);

            PresentationDefinitionDTO result = presentationService.constructPresentationDefinition(vcCredentialResponse);

            assertNotNull(result);
            assertEquals(1, result.getInputDescriptors().size());
            assertTrue(result.getInputDescriptors().get(0).getFormat().containsKey("dc+sd-jwt"));

            // Verify the filter pattern is null when type list is empty
            InputDescriptorDTO inputDescriptor = result.getInputDescriptors().get(0);
            FieldDTO field = inputDescriptor.getConstraints().getFields()[0];
            assertNull(field.getFilter().getPattern());
        }
    }

    @Test
    public void testConstructPresentationDefinitionForSdJwtWithMapTypeNullValue() {
        VCCredentialResponse vcCredentialResponse = createSDJwtCredentialResponse("vc+sd-jwt");

        // Create complex type structure with Map containing null _value
        Map<String, Object> typeMap = new HashMap<>();
        typeMap.put("_value", null);

        Map<String, Object> jwtPayload = Map.of("type", Arrays.asList("VerifiableCredential", typeMap));
        Map<String, Object> jwtHeaders = Map.of("alg", "ES256", "typ", "JWT");

        try (MockedStatic<JwtUtils> jwtUtilsMock = mockStatic(JwtUtils.class)) {
            jwtUtilsMock.when(() -> JwtUtils.extractJwtPayloadFromSdJwt(anyString())).thenReturn(jwtPayload);
            jwtUtilsMock.when(() -> JwtUtils.parseJwtHeader(anyString())).thenReturn(jwtHeaders);

            PresentationDefinitionDTO result = presentationService.constructPresentationDefinition(vcCredentialResponse);

            assertNotNull(result);
            assertEquals(1, result.getInputDescriptors().size());
            assertTrue(result.getInputDescriptors().get(0).getFormat().containsKey("vc+sd-jwt"));

            // Verify the filter pattern is null when _value is null
            InputDescriptorDTO inputDescriptor = result.getInputDescriptors().get(0);
            FieldDTO field = inputDescriptor.getConstraints().getFields()[0];
            assertNull(field.getFilter().getPattern());
        }
    }

    @Test
    public void testDirectPostResponseModeWithEmptyRedirectUri() throws Exception {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTOWithEmptyRedirectURI();
        presentationRequestDTO.setResponseMode("direct_post");
        presentationRequestDTO.setResponseUri("https://verifier.example.com/response");
        presentationRequestDTO.setState("test-state");
        presentationRequestDTO.setNonce("test-nonce");

        // Mock response with empty redirect_uri
        Map<String, Object> mockResponse = Map.of("redirect_uri", "");

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn((VCCredentialProperties) vcCredentialResponse.getCredential());
        when(restApiClient.postApi(anyString(), any(), any(), eq(Map.class))).thenReturn(mockResponse);

        String result = presentationService.authorizePresentation(presentationRequestDTO);

        assertEquals("https://verifier.example.com/response?status=vp_sent", result);
        verify(restApiClient).postApi(eq("https://verifier.example.com/response"), any(), any(), eq(Map.class));
    }

    @Test
    public void testAuthorizePresentationWithJsonProcessingException() throws Exception {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn((VCCredentialProperties) vcCredentialResponse.getCredential());

        // Mock objectMapper.writeValueAsString to throw JsonProcessingException
        when(objectMapper.writeValueAsString(any())).thenThrow(new JsonProcessingException("JSON processing error") {});

        // Act & Assert
        VPNotCreatedException exception = assertThrows(VPNotCreatedException.class, () -> {
            presentationService.authorizePresentation(presentationRequestDTO);
        });

        assertEquals(ErrorConstants.INVALID_REQUEST.getErrorCode() + " --> " + ErrorConstants.INVALID_REQUEST.getErrorMessage(), exception.getMessage());
    }

    @Test
    public void testRejectVerifierSuccess() throws Exception {
        String walletId = "wallet-123";
        ErrorDTO payload = new ErrorDTO("access_denied", "User denied authorization");

        // Create session data using the actual constructor (presentationId, authorizationRequest, createdAt, isPreregisteredWithWallet, matchedCredentials)
        String presentationId = "presentation-123";
        String authorizationRequest = "authorization-request";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId,
                authorizationRequest,
                Instant.now(),
                true,
                null
        );

        VerifierResponse mockResponse = mock(VerifierResponse.class);
        when(mockResponse.getRedirectUri()).thenReturn("https://verifier.example.com/redirect");
        when(openID4VPService.sendErrorToVerifier(eq(sessionData), eq(payload))).thenReturn(mockResponse);

        // Should not throw
        SubmitPresentationResponseDTO result = presentationService.rejectVerifier(walletId, sessionData, payload);

        assertNotNull(result);
        assertEquals("https://verifier.example.com/redirect", result.getRedirectUri());
        assertEquals(REJECTED_VERIFIER.getErrorCode(), result.getStatus());
        verify(openID4VPService).sendErrorToVerifier(eq(sessionData), eq(payload));
    }

    @Test(expected = VPErrorNotSentException.class)
    public void testRejectVerifierNullOpenID4VPInstance() throws Exception {
        String walletId = "wallet-123";
        ErrorDTO payload = new ErrorDTO("access_denied", "User denied authorization");

        // Create session data that would cause underlying OpenID4VP to fail (simulate by making the mocked service throw)
        String presentationId = "presentation-123";
        String authorizationRequest = "authorization-request";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId,
                authorizationRequest,
                Instant.now(),
                false,
                null
        );

        // Simulate underlying service throwing an exception which PresentationServiceImpl should wrap into VPErrorNotSentException
        doThrow(new IllegalArgumentException("OpenID4VP instance is null")).when(openID4VPService).sendErrorToVerifier(eq(sessionData), eq(payload));

        presentationService.rejectVerifier(walletId, sessionData, payload);
    }

    @Test(expected = VPErrorNotSentException.class)
    public void testRejectVerifierMissingOpenID4VPInstance() throws Exception {
        String walletId = "wallet-123";
        ErrorDTO payload = new ErrorDTO("access_denied", "User denied authorization");

        String presentationId = "presentation-456";
        String authorizationRequest = "authorization-request-2";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId,
                authorizationRequest,
                Instant.now(),
                true,
                null
        );

        // Simulate sendErrorToVerifier throwing IOException
        doThrow(new IOException("network failure")).when(openID4VPService).sendErrorToVerifier(eq(sessionData), eq(payload));

        presentationService.rejectVerifier(walletId, sessionData, payload);
    }

    @Test(expected = VPErrorNotSentException.class)
    public void testRejectVerifierNullSessionData() throws Exception {
        String walletId = "wallet-123";
        ErrorDTO payload = new ErrorDTO("access_denied", "User denied authorization");

        // Configure mock to throw when sendErrorToVerifier is invoked with null sessionData and the same payload instance
        doThrow(new IllegalArgumentException("Invalid presentation session data"))
                .when(openID4VPService).sendErrorToVerifier(isNull(), eq(payload));

        // Call the service with null session data — PresentationServiceImpl should catch the underlying exception
        // and rethrow VPErrorNotSentException, which this test now expects.
        presentationService.rejectVerifier(walletId, null, payload);
    }

    @Test
    public void testRejectVerifierWithDifferentErrorCodes() throws Exception {
        String walletId = "wallet-123";
        String presentationId = "presentation-789";
        String authorizationRequest = "authorization-request-3";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId,
                authorizationRequest,
                Instant.now(),
                true,
                null
        );

        ErrorDTO payload = new ErrorDTO("interaction_required", "Interaction required from user");
        VerifierResponse mockResponse = mock(VerifierResponse.class);
        when(mockResponse.getRedirectUri()).thenReturn("https://verifier.example.com/redirect");
        when(openID4VPService.sendErrorToVerifier(eq(sessionData), eq(payload))).thenReturn(mockResponse);

        SubmitPresentationResponseDTO result = presentationService.rejectVerifier(walletId, sessionData, payload);

        assertNotNull(result);
        assertEquals("https://verifier.example.com/redirect", result.getRedirectUri());
        verify(openID4VPService).sendErrorToVerifier(eq(sessionData), eq(payload));
    }

}