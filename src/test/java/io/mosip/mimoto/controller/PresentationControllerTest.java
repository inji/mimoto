package io.mosip.mimoto.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.InvalidVerifierException;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.openID4VP.constants.SpecVersion;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = PresentationController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
@TestPropertySource(properties = {
        "mosip.inji.ovp.error.redirect.url.pattern=%s?error_code=%s&error_message=%s",
        "mosip.inji.web.redirect.url=https://inji.web.redirect.url"
})
public class PresentationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private PresentationService presentationService;

    @MockBean
    private VerifierService verifierService;

    @MockBean
    private ObjectMapper objectMapper;

    private static final String RESPONSE_TYPE = "vp_token";
    private static final String RESOURCE = "https://example.com/resource";
    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String PRESENTATION_DEFINITION_JSON = "{\"id\":\"test\",\"input_descriptors\":[]}";
    private static final String SUCCESS_REDIRECT_URL = "https://success.redirect.url";
    private static final String RESPONSE_URI = "https://example.com/v0/verify/vp-submission/direct-post?session=abc";

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    private VerifierDTO createVerifierDTO(SpecVersion specVersion) {
        return VerifierDTO.builder()
                .clientId(CLIENT_ID)
                .specVersion(specVersion)
                .build();
    }

    @Test
    public void testPerformAuthorizationSuccess() throws Exception {
        // Arrange
        PresentationDefinitionDTO mockPresentationDefinitionDTO = new PresentationDefinitionDTO();
        when(objectMapper.readValue(PRESENTATION_DEFINITION_JSON, PresentationDefinitionDTO.class))
                .thenReturn(mockPresentationDefinitionDTO);
        when(presentationService.processVPRequest(any(PresentationRequestDTO.class), any(SpecVersion.class)))
                .thenReturn(SUCCESS_REDIRECT_URL);
        when(verifierService.validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI))
                .thenReturn(createVerifierDTO(SpecVersion.DRAFT_23));

        // Act & Assert
        mockMvc.perform(get("/authorize")
                        .param("response_type", RESPONSE_TYPE)
                        .param("resource", RESOURCE)
                        .param("presentation_definition", PRESENTATION_DEFINITION_JSON)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("response_uri", RESPONSE_URI))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(SUCCESS_REDIRECT_URL));

        // Verify service calls
        verify(verifierService).validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI);
        verify(objectMapper).readValue(PRESENTATION_DEFINITION_JSON, PresentationDefinitionDTO.class);

        ArgumentCaptor<PresentationRequestDTO> captor = ArgumentCaptor.forClass(PresentationRequestDTO.class);
        verify(presentationService).processVPRequest(captor.capture(), eq(SpecVersion.DRAFT_23));

        PresentationRequestDTO capturedRequest = captor.getValue();
        assertEquals(RESPONSE_TYPE, capturedRequest.getResponseType());
        assertEquals(RESOURCE, capturedRequest.getResource());
        assertEquals(CLIENT_ID, capturedRequest.getClientId());
        assertEquals(REDIRECT_URI, capturedRequest.getRedirectUri());
        assertEquals(mockPresentationDefinitionDTO, capturedRequest.getPresentationDefinition());
    }

    @Test
    public void testPerformAuthorizationInvalidVerifierException() throws Exception {
        // Arrange
        String errorCode = "INVALID_VERIFIER";
        String errorMessage = "Invalid verifier provided";
        InvalidVerifierException exception = new InvalidVerifierException(errorCode, errorMessage);

        doThrow(exception).when(verifierService).validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI);

        String expectedRedirectUrl = String.format(
                "https://inji.web.redirect.url?error_code=%s&error_message=%s",
                errorCode,
                URLEncoder.encode(errorMessage, StandardCharsets.UTF_8)
        );

        // Act & Assert
        mockMvc.perform(get("/authorize")
                        .param("response_type", RESPONSE_TYPE)
                        .param("resource", RESOURCE)
                        .param("presentation_definition", PRESENTATION_DEFINITION_JSON)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("response_uri", RESPONSE_URI))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirectUrl));

        verify(verifierService).validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI);
        verify(presentationService, never()).processVPRequest(any(), any());
    }

    @Test
    public void testPerformAuthorizationVPNotCreatedException() throws Exception {
        // Arrange
        String errorCode = "VP_NOT_CREATED";
        String errorMessage = "VP creation failed";
        VPNotCreatedException exception = new VPNotCreatedException(errorCode, errorMessage);

        PresentationDefinitionDTO mockPresentationDefinitionDTO = new PresentationDefinitionDTO();
        when(objectMapper.readValue(PRESENTATION_DEFINITION_JSON, PresentationDefinitionDTO.class))
                .thenReturn(mockPresentationDefinitionDTO);
        when(verifierService.validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI))
                .thenReturn(createVerifierDTO(SpecVersion.DRAFT_23));
        when(presentationService.processVPRequest(any(PresentationRequestDTO.class), any(SpecVersion.class)))
                .thenThrow(exception);

        String expectedRedirectUrl = String.format(
                "%s?error_code=%s&error_message=%s",
                REDIRECT_URI,
                errorCode,
                URLEncoder.encode(errorMessage, StandardCharsets.UTF_8)
        );

        // Act & Assert
        mockMvc.perform(get("/authorize")
                        .param("response_type", RESPONSE_TYPE)
                        .param("resource", RESOURCE)
                        .param("presentation_definition", PRESENTATION_DEFINITION_JSON)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("response_uri", RESPONSE_URI))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirectUrl));

        verify(verifierService).validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI);
        verify(presentationService).processVPRequest(any(PresentationRequestDTO.class), any(SpecVersion.class));
    }

    @Test
    public void testPerformAuthorizationInvalidCredentialResourceException() throws Exception {
        // Arrange
        String errorCode = "INVALID_CREDENTIAL_RESOURCE";
        String errorMessage = "Invalid credential resource";
        InvalidCredentialResourceException exception = new InvalidCredentialResourceException(errorCode, errorMessage);

        PresentationDefinitionDTO mockPresentationDefinitionDTO = new PresentationDefinitionDTO();
        when(objectMapper.readValue(PRESENTATION_DEFINITION_JSON, PresentationDefinitionDTO.class))
                .thenReturn(mockPresentationDefinitionDTO);
        when(verifierService.validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI))
                .thenReturn(createVerifierDTO(SpecVersion.DRAFT_23));
        when(presentationService.processVPRequest(any(PresentationRequestDTO.class), any(SpecVersion.class)))
                .thenThrow(exception);

        String expectedRedirectUrl = String.format(
                "%s?error_code=%s&error_message=%s",
                REDIRECT_URI,
                errorCode,
                URLEncoder.encode(errorMessage, StandardCharsets.UTF_8)
        );

        // Act & Assert
        mockMvc.perform(get("/authorize")
                        .param("response_type", RESPONSE_TYPE)
                        .param("resource", RESOURCE)
                        .param("presentation_definition", PRESENTATION_DEFINITION_JSON)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("response_uri", RESPONSE_URI))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirectUrl));

        verify(verifierService).validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI);
        verify(presentationService).processVPRequest(any(PresentationRequestDTO.class), any(SpecVersion.class));
    }

    @Test
    public void testPerformAuthorizationGenericException() throws Exception {
        // Arrange
        RuntimeException exception = new RuntimeException("Unexpected error occurred");

        PresentationDefinitionDTO mockPresentationDefinitionDTO = new PresentationDefinitionDTO();
        when(objectMapper.readValue(PRESENTATION_DEFINITION_JSON, PresentationDefinitionDTO.class))
                .thenReturn(mockPresentationDefinitionDTO);
        when(verifierService.validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI))
                .thenReturn(createVerifierDTO(SpecVersion.DRAFT_23));
        when(presentationService.processVPRequest(any(PresentationRequestDTO.class), any(SpecVersion.class)))
                .thenThrow(exception);

        String expectedRedirectUrl = String.format(
                "%s?error_code=%s&error_message=%s",
                REDIRECT_URI,
                ErrorConstants.INTERNAL_SERVER_ERROR.getErrorCode(),
                URLEncoder.encode(ErrorConstants.INTERNAL_SERVER_ERROR.getErrorMessage(), StandardCharsets.UTF_8)
        );

        // Act & Assert
        mockMvc.perform(get("/authorize")
                        .param("response_type", RESPONSE_TYPE)
                        .param("resource", RESOURCE)
                        .param("presentation_definition", PRESENTATION_DEFINITION_JSON)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("response_uri", RESPONSE_URI))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirectUrl));

        verify(verifierService).validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI);
        verify(presentationService).processVPRequest(any(PresentationRequestDTO.class), any(SpecVersion.class));
    }

    @Test
    public void testPerformAuthorizationJsonParsingException() throws Exception {
        // Arrange
        when(objectMapper.readValue(PRESENTATION_DEFINITION_JSON, PresentationDefinitionDTO.class))
                .thenThrow(new RuntimeException("JSON parsing failed"));
        when(verifierService.validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI))
                .thenReturn(createVerifierDTO(SpecVersion.DRAFT_23));

        String expectedRedirectUrl = String.format(
                "%s?error_code=%s&error_message=%s",
                REDIRECT_URI,
                ErrorConstants.INTERNAL_SERVER_ERROR.getErrorCode(),
                URLEncoder.encode(ErrorConstants.INTERNAL_SERVER_ERROR.getErrorMessage(), StandardCharsets.UTF_8)
        );

        // Act & Assert
        mockMvc.perform(get("/authorize")
                        .param("response_type", RESPONSE_TYPE)
                        .param("resource", RESOURCE)
                        .param("presentation_definition", PRESENTATION_DEFINITION_JSON)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("response_uri", RESPONSE_URI))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirectUrl));

        verify(verifierService).validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI);
        verify(presentationService, never()).processVPRequest(any(), any());
    }

    @Test
    public void testPerformAuthorizationMissingRequiredParameters() throws Exception {
        // Test missing response_type
        mockMvc.perform(get("/authorize")
                        .param("resource", RESOURCE)
                        .param("presentation_definition", PRESENTATION_DEFINITION_JSON)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI))
                .andExpect(status().isBadRequest());

        // Test missing resource
        mockMvc.perform(get("/authorize")
                        .param("response_type", RESPONSE_TYPE)
                        .param("presentation_definition", PRESENTATION_DEFINITION_JSON)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI))
                .andExpect(status().isBadRequest());

        // Test missing client_id (presentation_definition is now optional)
        mockMvc.perform(get("/authorize")
                        .param("response_type", RESPONSE_TYPE)
                        .param("resource", RESOURCE)
                        .param("presentation_definition", PRESENTATION_DEFINITION_JSON)
                        .param("redirect_uri", REDIRECT_URI))
                .andExpect(status().isBadRequest());

        // Verify no service calls were made
        verify(verifierService, never()).validateVerifier(anyString(), anyString(), anyString());
        verify(presentationService, never()).processVPRequest(any(), any());
    }

    @Test
    public void testPerformAuthorizationEmptyParameters() throws Exception {
        // Arrange
        doThrow(new InvalidVerifierException("EMPTY_CLIENT_ID", "Client ID cannot be empty"))
                .when(verifierService).validateVerifier("", "", "");

        String expectedRedirectUrl = String.format(
                "https://inji.web.redirect.url?error_code=%s&error_message=%s",
                "EMPTY_CLIENT_ID",
                URLEncoder.encode("Client ID cannot be empty", StandardCharsets.UTF_8)
        );

        // Act & Assert
        mockMvc.perform(get("/authorize")
                        .param("response_type", "")
                        .param("resource", "")
                        .param("presentation_definition", "")
                        .param("client_id", "")
                        .param("redirect_uri", "")
                        .param("response_uri", ""))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirectUrl));
    }

    @Test
    public void testPerformAuthorizationSpecialCharactersInParameters() throws Exception {
        // Arrange
        String specialClientId = "client@#$%^&*()";
        String specialRedirectUri = "https://example.com/callback?param=value&other=test";
        String specialResource = "https://example.com/resource?id=123&type=credential";

        PresentationDefinitionDTO mockPresentationDefinitionDTO = new PresentationDefinitionDTO();
        when(objectMapper.readValue(PRESENTATION_DEFINITION_JSON, PresentationDefinitionDTO.class))
                .thenReturn(mockPresentationDefinitionDTO);
        String specialResponseUri = "https://example.com/v0/verify/vp-submission/direct-post?session=abc";
        when(presentationService.processVPRequest(any(PresentationRequestDTO.class), any(SpecVersion.class)))
                .thenReturn(SUCCESS_REDIRECT_URL);
        when(verifierService.validateVerifier(specialClientId, specialResponseUri, specialRedirectUri))
                .thenReturn(createVerifierDTO(SpecVersion.DRAFT_23));

        // Act & Assert
        mockMvc.perform(get("/authorize")
                        .param("response_type", RESPONSE_TYPE)
                        .param("resource", specialResource)
                        .param("presentation_definition", PRESENTATION_DEFINITION_JSON)
                        .param("client_id", specialClientId)
                        .param("redirect_uri", specialRedirectUri)
                        .param("response_uri", specialResponseUri))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(SUCCESS_REDIRECT_URL));

        verify(verifierService).validateVerifier(specialClientId, specialResponseUri, specialRedirectUri);
        verify(presentationService).processVPRequest(any(PresentationRequestDTO.class), any(SpecVersion.class));
    }

// Add to PresentationControllerTest.java

    @Test
    public void testPerformAuthorizationWithInvalidHttpMethod() throws Exception {
        // POST instead of GET should return 405 Method Not Allowed
        mockMvc.perform(post("/authorize")
                        .param("response_type", RESPONSE_TYPE)
                        .param("resource", RESOURCE)
                        .param("presentation_definition", PRESENTATION_DEFINITION_JSON)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI))
                .andExpect(status().isMethodNotAllowed());
    }

    @Test
    public void testPerformAuthorizationWithExtraParameters() throws Exception {
        PresentationDefinitionDTO mockPresentationDefinitionDTO = new PresentationDefinitionDTO();
        when(objectMapper.readValue(PRESENTATION_DEFINITION_JSON, PresentationDefinitionDTO.class))
                .thenReturn(mockPresentationDefinitionDTO);
        when(presentationService.processVPRequest(any(PresentationRequestDTO.class), any(SpecVersion.class)))
                .thenReturn(SUCCESS_REDIRECT_URL);
        when(verifierService.validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI))
                .thenReturn(createVerifierDTO(SpecVersion.DRAFT_23));

        mockMvc.perform(get("/authorize")
                        .param("response_type", RESPONSE_TYPE)
                        .param("resource", RESOURCE)
                        .param("presentation_definition", PRESENTATION_DEFINITION_JSON)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("response_uri", RESPONSE_URI)
                        .param("extra_param", "extra_value"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(SUCCESS_REDIRECT_URL));
    }

    @Test
    public void testPerformAuthorizationWithMalformedPresentationDefinitionJson() throws Exception {
        String malformedJson = "{invalid_json}";
        when(objectMapper.readValue(malformedJson, PresentationDefinitionDTO.class))
                .thenThrow(new RuntimeException("Malformed JSON"));
        when(verifierService.validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI))
                .thenReturn(createVerifierDTO(SpecVersion.DRAFT_23));

        String expectedRedirectUrl = String.format(
                "%s?error_code=%s&error_message=%s",
                REDIRECT_URI,
                ErrorConstants.INTERNAL_SERVER_ERROR.getErrorCode(),
                URLEncoder.encode(ErrorConstants.INTERNAL_SERVER_ERROR.getErrorMessage(), StandardCharsets.UTF_8)
        );

        mockMvc.perform(get("/authorize")
                        .param("response_type", RESPONSE_TYPE)
                        .param("resource", RESOURCE)
                        .param("presentation_definition", malformedJson)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("response_uri", RESPONSE_URI))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirectUrl));
    }

    @Test
    public void testPerformAuthorizationWithNullParameters() throws Exception {
        mockMvc.perform(get("/authorize")
                        .param("response_type", (String) null)
                        .param("resource", (String) null)
                        .param("client_id", (String) null)
                        .param("redirect_uri", (String) null))
                .andExpect(status().isBadRequest());

        verify(verifierService, never()).validateVerifier(anyString(), anyString(), anyString());
        verify(presentationService, never()).processVPRequest(any(), any());
    }

    @Test
    public void should_routeToDcqlFlow_when_verifierSpecVersionIsV1() throws Exception {
        // Arrange - V1 verifier with dcql_query
        String dcqlQueryJson = "{\"credentials\":[{\"id\":\"cred1\",\"format\":\"dc+sd-jwt\"}]}";
        when(verifierService.validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI))
                .thenReturn(createVerifierDTO(SpecVersion.V1));
        when(presentationService.processVPRequest(any(PresentationRequestDTO.class), eq(SpecVersion.V1)))
                .thenReturn(SUCCESS_REDIRECT_URL);

        // Act & Assert
        mockMvc.perform(get("/authorize")
                        .param("response_type", RESPONSE_TYPE)
                        .param("resource", RESOURCE)
                        .param("dcql_query", dcqlQueryJson)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("response_uri", RESPONSE_URI))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(SUCCESS_REDIRECT_URL));

        ArgumentCaptor<PresentationRequestDTO> captor = ArgumentCaptor.forClass(PresentationRequestDTO.class);
        verify(presentationService).processVPRequest(captor.capture(), eq(SpecVersion.V1));

        PresentationRequestDTO capturedRequest = captor.getValue();
        assertEquals(dcqlQueryJson, capturedRequest.getDcqlQuery());
        assertNull(capturedRequest.getPresentationDefinition());
    }

    @Test
    public void should_rejectAuthorize_when_bothPresentationDefinitionAndDcqlQueryMissing() throws Exception {
        when(verifierService.validateVerifier(CLIENT_ID, RESPONSE_URI, REDIRECT_URI))
                .thenReturn(createVerifierDTO(SpecVersion.V1));

        String expectedRedirectUrl = String.format(
                "%s?error_code=%s&error_message=%s",
                REDIRECT_URI,
                ErrorConstants.INVALID_REQUEST.getErrorCode(),
                URLEncoder.encode(ErrorConstants.INVALID_REQUEST.getErrorMessage(), StandardCharsets.UTF_8)
        );

        mockMvc.perform(get("/authorize")
                        .param("response_type", RESPONSE_TYPE)
                        .param("resource", RESOURCE)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("response_uri", RESPONSE_URI))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirectUrl));

        verify(presentationService, never()).processVPRequest(any(), any());
    }

}
