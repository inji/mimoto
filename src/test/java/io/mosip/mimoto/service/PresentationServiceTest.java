package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponseProof;
import io.mosip.openID4VP.constants.SpecVersion;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.openid.presentation.FieldDTO;
import io.mosip.mimoto.dto.openid.presentation.InputDescriptorDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.impl.DataShareServiceImpl;
import io.mosip.mimoto.service.impl.PresentationServiceImpl;
import io.mosip.mimoto.util.JwtUtils;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

import static io.mosip.mimoto.util.JwtUtils.parseJwtHeader;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class PresentationServiceTest {
    @Mock
    DataShareServiceImpl dataShareService;

    @Mock
    ObjectMapper objectMapper;

    @Mock
    RestApiClient restApiClient;

    PresentationServiceImpl presentationService;

    String walletId, clientId, urlEncodedVPAuthorizationRequest;
    VerifiersDTO verifiersDTO;
    VerifierDTO verifierDTO;
    List<Verifier> preRegisteredVerifiers;
    UUID fixedUuid;
    Instant fixedInstant;

    @Before
    public void setup() throws JsonProcessingException {
        presentationService = new PresentationServiceImpl(dataShareService, objectMapper, restApiClient, "%s#vp_token=%s&presentation_submission=%s", "%s#vp_token=%s", 65536);
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
                false,
                SpecVersion.V1
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
        presentationRequestDTO.setResponseMode("direct_post");
        presentationRequestDTO.setResponseUri("https://verifier.example.com/response");

        Map<String, Object> mockPostResponse = Map.of("redirect_uri", "https://verifier.example.com/success");

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn((VCCredentialProperties) vcCredentialResponse.getCredential());
        when(restApiClient.postApi(anyString(), any(), any(), eq(Map.class))).thenReturn(mockPostResponse);

        String actualRedirectUrl = presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);

        assertEquals("https://verifier.example.com/success", actualRedirectUrl);
        verify(restApiClient).postApi(eq("https://verifier.example.com/response"), any(), any(), eq(Map.class));
    }

    @Test
    public void authorizePresentation_redirectMode_returnsRedirectUrlWithVpTokenAndPresentationSubmission() throws Exception {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        presentationRequestDTO.setResponseMode(null);

        doReturn(vcCredentialResponse).when(dataShareService).downloadCredentialFromDataShare(eq(presentationRequestDTO));
        doReturn((VCCredentialProperties) vcCredentialResponse.getCredential()).when(objectMapper)
                .convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class));
        doReturn("test-data").when(objectMapper).writeValueAsString(any());

        String vpToken = "test-data";
        String presentationSubmission = "test-data";
        String redirectUri = presentationRequestDTO.getRedirectUri();
        String expected = String.format("%s#vp_token=%s&presentation_submission=%s",
                redirectUri,
                Base64.getUrlEncoder().encodeToString(vpToken.getBytes(StandardCharsets.UTF_8)),
                URLEncoder.encode(presentationSubmission, StandardCharsets.UTF_8));

        String actual = presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);

        assertEquals(expected, actual);
        verify(restApiClient, never()).postApi(anyString(), any(), any(), eq(Map.class));
    }

    @Test
    public void authorizePresentation_redirectMode_throwsWhenRedirectUrlExceedsMaxHeaderSize() throws Exception {
        PresentationServiceImpl serviceWithSmallHeaderLimit = new PresentationServiceImpl(
                dataShareService,
                objectMapper,
                restApiClient,
                "%s#vp_token=%s&presentation_submission=%s",
                "%s#vp_token=%s",
                200
        );

        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        presentationRequestDTO.setResponseMode(null);

        doReturn(vcCredentialResponse).when(dataShareService).downloadCredentialFromDataShare(eq(presentationRequestDTO));
        doReturn((VCCredentialProperties) vcCredentialResponse.getCredential()).when(objectMapper)
                .convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class));
        doReturn("p".repeat(500)).when(objectMapper).writeValueAsString(any());

        VPNotCreatedException ex = assertThrows(VPNotCreatedException.class,
                () -> serviceWithSmallHeaderLimit.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23));

        assertEquals(
                ErrorConstants.URI_TOO_LONG.getErrorCode() + " --> " + ErrorConstants.URI_TOO_LONG.getErrorMessage(),
                ex.getMessage());
        verify(restApiClient, never()).postApi(anyString(), any(), any(), eq(Map.class));
    }

    @Test(expected = VPNotCreatedException.class)
    public void credentialProofMismatchWithVPRequest() throws IOException {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("RSASignature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn((VCCredentialProperties) vcCredentialResponse.getCredential());
        presentationService.processVPRequest(TestUtilities.getPresentationRequestDTO(), SpecVersion.DRAFT_23);
    }

    @Test
    public void sdJwtCredentialMatchingWithVPRequest() throws Exception {
        VCCredentialResponse vcCredentialResponse = createSDJwtCredentialResponse("vc+sd-jwt");
        PresentationRequestDTO presentationRequestDTO = createSDJwtPresentationRequest();
        presentationRequestDTO.setResponseMode("direct_post");
        presentationRequestDTO.setResponseUri("https://verifier.example.com/response");
        Map<String, Object> jwtHeaders = Map.of("alg", "ES256", "typ", "JWT");
        Map<String, Object> mockPostResponse = Map.of("redirect_uri", "https://verifier.example.com/success");
        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(String.class)))
                .thenReturn("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.test.signature");
        when(restApiClient.postApi(anyString(), any(), any(), eq(Map.class))).thenReturn(mockPostResponse);

        try (MockedStatic<JwtUtils> jwtUtilsMock = mockStatic(JwtUtils.class)) {
            jwtUtilsMock.when(() -> parseJwtHeader(anyString())).thenReturn(jwtHeaders);

            String actualRedirectUrl = presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);

            assertEquals("https://verifier.example.com/success", actualRedirectUrl);
            verify(restApiClient).postApi(eq("https://verifier.example.com/response"), any(), any(), eq(Map.class));
        }
    }

    @Test(expected = VPNotCreatedException.class)
    public void nullPresentationDefinitionWithVPRequest() throws IOException {
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        presentationRequestDTO.setPresentationDefinition(null);

        presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);
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
    public void constructDcqlQueryForLdpVcCredential() {
        VCCredentialResponse vcCredentialResponse = createLdpVcCredentialResponse();
        VCCredentialProperties credential = (VCCredentialProperties) vcCredentialResponse.getCredential();
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn(credential);

        Map<String, Object> result = presentationService.constructDcqlQuery(vcCredentialResponse);

        assertNotNull(result);
        assertTrue(result.containsKey("credentials"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get("credentials");
        assertEquals(1, credentials.size());
        assertEquals(CredentialFormat.LDP_VC.getFormat(), credentials.get(0).get("format"));
        assertNotNull(credentials.get(0).get("id"));
        assertEquals(false, credentials.get(0).get("require_cryptographic_holder_binding"));
        assertTrue(((Map<?, ?>) credentials.get(0).get("meta")).containsKey("type_values"));
    }

    @Test
    public void constructDcqlQueryForSdJwtCredentialUsesVct() {
        VCCredentialResponse vcCredentialResponse = createSDJwtCredentialResponse("dc+sd-jwt");
        Map<String, Object> jwtPayload = Map.of("vct", "https://example.com/TestCredential");

        try (MockedStatic<JwtUtils> jwtUtilsMock = mockStatic(JwtUtils.class)) {
            jwtUtilsMock.when(() -> JwtUtils.extractJwtPayloadFromSdJwt(anyString())).thenReturn(jwtPayload);

            Map<String, Object> result = presentationService.constructDcqlQuery(vcCredentialResponse);

            assertNotNull(result);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get("credentials");
            assertEquals("dc+sd-jwt", credentials.get(0).get("format"));
            assertEquals(false, credentials.get(0).get("require_cryptographic_holder_binding"));
            @SuppressWarnings("unchecked")
            Map<String, Object> meta = (Map<String, Object>) credentials.get(0).get("meta");
            assertEquals(List.of("https://example.com/TestCredential"), meta.get("vct_values"));
        }
    }

    @Test
    public void authorizeDcqlPresentation_directPost_sendsRawJsonVpTokenMapWithoutPresentationSubmission() throws Exception {
        VCCredentialResponse vcCredentialResponse = createLdpVcCredentialResponse();
        VCCredentialProperties credential = (VCCredentialProperties) vcCredentialResponse.getCredential();

        String queryId = "0b362b84-25ad-4e32-9234-dea6807d7451";
        String dcqlQuery = "{\"credentials\":[{\"id\":\"" + queryId + "\",\"format\":\"ldp_vc\",\"require_cryptographic_holder_binding\":false}]}";
        Map<String, Object> dcqlQueryMap = Map.of(
                "credentials", List.of(Map.of(
                        "id", queryId,
                        "format", "ldp_vc",
                        "require_cryptographic_holder_binding", false)));

        PresentationRequestDTO presentationRequestDTO = PresentationRequestDTO.builder()
                .resource("http://datashare.example/resource")
                .dcqlQuery(dcqlQuery)
                .clientId("test-client")
                .responseMode("direct_post")
                .responseUri("https://verifier.example.com/v2/vp-submission/direct-post")
                .redirectUri("https://verifier.example.com/redirect")
                .state("session-state")
                .build();

        Map<String, Object> mockPostResponse = Map.of("redirect_uri", "https://verifier.example.com/success");

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.readValue(eq(dcqlQuery), eq(Map.class))).thenReturn(dcqlQueryMap);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn(credential);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"0b362b84-25ad-4e32-9234-dea6807d7451\":[{}]}");
        when(restApiClient.postApi(anyString(), any(), any(), eq(Map.class))).thenReturn(mockPostResponse);

        String redirect = presentationService.processVPRequest(presentationRequestDTO, SpecVersion.V1);

        assertEquals("https://verifier.example.com/success", redirect);

        ArgumentCaptor<Object> vpTokenMapCaptor = ArgumentCaptor.forClass(Object.class);
        verify(objectMapper).writeValueAsString(vpTokenMapCaptor.capture());
        @SuppressWarnings("unchecked")
        Map<String, Object> capturedVpTokenMap = (Map<String, Object>) vpTokenMapCaptor.getValue();
        @SuppressWarnings("unchecked")
        List<Object> presentations = (List<Object>) capturedVpTokenMap.get(queryId);
        assertEquals(1, presentations.size());
        // Data Share DCQL always submits plain VC, not unbound VP
        assertSame(credential, presentations.get(0));

        ArgumentCaptor<MultiValueMap> bodyCaptor = ArgumentCaptor.forClass(MultiValueMap.class);
        verify(restApiClient).postApi(
                eq("https://verifier.example.com/v2/vp-submission/direct-post"),
                eq(MediaType.APPLICATION_FORM_URLENCODED),
                bodyCaptor.capture(),
                eq(Map.class));

        MultiValueMap<String, String> body = bodyCaptor.getValue();
        assertEquals("{\"0b362b84-25ad-4e32-9234-dea6807d7451\":[{}]}", body.getFirst("vp_token"));
        assertNull(body.getFirst("presentation_submission"));
        assertEquals("session-state", body.getFirst("state"));
    }

    // Tests for handleVPAuthorizationRequest removed - method moved to WalletPresentationService

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

        presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);
    }

    @Test(expected = VPNotCreatedException.class)
    public void authorizePresentationUnsupportedCredentialFormatThrowsException() throws Exception {
        VCCredentialResponse vcCredentialResponse = new VCCredentialResponse();
        vcCredentialResponse.setCredential("dummy");
        vcCredentialResponse.setFormat("unsupported-format");

        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);

        presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);
    }

    @Test(expected = RuntimeException.class)
    public void authorizePresentationObjectMapperThrowsException() throws Exception {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenThrow(new RuntimeException("Mapping error"));
        presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);
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

        String result = presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);

        assertEquals("https://verifier.example.com/success", result);
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

        String result = presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);

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

            presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);
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

        presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);
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

        String result = presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);

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

        presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);
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

        String result = presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);

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
            presentationService.processVPRequest(presentationRequestDTO, SpecVersion.DRAFT_23);
        });

        assertEquals(ErrorConstants.INVALID_REQUEST.getErrorCode() + " --> " + ErrorConstants.INVALID_REQUEST.getErrorMessage(), exception.getMessage());
    }

    // Tests for rejectVerifier removed - method moved to WalletPresentationService

    @Test
    public void constructPresentationDefinitionWithRenderMethod() throws Exception{
        VCCredentialResponse vcCredentialResponse = new VCCredentialResponse();
        vcCredentialResponse.setFormat(CredentialFormat.LDP_VC.getFormat());

        Map<String, Object> template = Map.of(
            "id", "https://degree.example/credential-templates/bachelors",
            "mediaType", "image/svg+xml",
            "digestMultibase", "zQmerWC85Wg6wFl9znFCwYxApG270iEu5h6JqWAPdhyxz2dR"
        );
        Map<String, Object> renderMethod = Map.of(
            "type", "TemplateRenderMethod",
            "renderSuite", "svg-mustache",
            "template", template
        );

        VCCredentialProperties credential = new VCCredentialProperties();
        credential.setType(Arrays.asList("VerifiableCredential", "TestCredential"));
        credential.setContext("https://www.w3.org/2018/credentials/v2");
        credential.setRenderMethod(renderMethod);
        VCCredentialResponseProof proof = new VCCredentialResponseProof();
        proof.setType("Ed25519Signature2020");
        credential.setProof(proof);

        vcCredentialResponse.setCredential(credential);

        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn(credential);

        PresentationDefinitionDTO result = presentationService.constructPresentationDefinition(vcCredentialResponse);

        assertNotNull(result);

        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(credential);
        assertTrue(json.contains("renderMethod"));
    }

    @Test
    public void constructPresentationDefinitionWithoutRenderMethod() throws Exception {
        VCCredentialResponse vcCredentialResponse = new VCCredentialResponse();
        vcCredentialResponse.setFormat(CredentialFormat.LDP_VC.getFormat());

        VCCredentialProperties credential = new VCCredentialProperties();
        credential.setType(Arrays.asList("VerifiableCredential", "TestCredential"));
        credential.setContext("https://www.w3.org/2018/credentials/v2");
        // renderMethod not set
        VCCredentialResponseProof proof = new VCCredentialResponseProof();
        proof.setType("Ed25519Signature2020");
        credential.setProof(proof);

        vcCredentialResponse.setCredential(credential);

        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn(credential);

        PresentationDefinitionDTO result = presentationService.constructPresentationDefinition(vcCredentialResponse);

        assertNotNull(result);

        //Not mocking the ObjectMapper here to test the actual serialization : renderMethod should be absent
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(credential);
        assertFalse(json.contains("renderMethod"));
    }
}