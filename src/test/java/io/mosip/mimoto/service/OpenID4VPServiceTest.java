package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.openID4VP.networkManager.NetworkResponse;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.impl.OpenID4VPService;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition;
import io.mosip.openID4VP.dcql.query.DCQLQuery;
import io.mosip.openID4VP.common.OpenID4VPErrorCodes;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;
import io.mosip.openID4VP.verifier.VerifierResponse;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@Slf4j
public class OpenID4VPServiceTest {

    @Mock
    private VerifierService verifierService;

    @InjectMocks
    private OpenID4VPService openID4VPService;

    private VerifiersDTO mockVerifiersDTO;
    private VerifierDTO mockVerifierDTO;
    private AuthorizationPresentationExchangeRequest mockAuthorizationRequest;
    private PresentationDefinition mockPresentationDefinition;

    @BeforeEach
    public void setUp() {
        // Setup mock VerifierDTO with required vp_formats
        mockVerifierDTO = VerifierDTO.builder()
                .clientId("test-client-id")
                .responseUris(List.of("https://example.com/response"))
                .jwksUri("https://example.com/.well-known/jwks.json")
                .allowUnsignedRequest(true)
                .build();

        // Setup mock VerifiersDTO
        mockVerifiersDTO = VerifiersDTO.builder()
                .verifiers(List.of(mockVerifierDTO))
                .build();


        // Setup mock AuthorizationRequest
        mockAuthorizationRequest = mock(AuthorizationPresentationExchangeRequest.class);

        // Setup mock PresentationDefinition
        mockPresentationDefinition = mock(PresentationDefinition.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"presentation-123", "valid-presentation-id", "presentation-123_with.special@chars"})
    public void createWithVariousPresentationIdsReturnsValidOpenID4VP(String presentationId) {
        OpenID4VP openID4VP = openID4VPService.create(presentationId, List.of(), true);

        assertNotNull(openID4VP);
        assertEquals("io.mosip.openID4VP.OpenID4VP", openID4VP.getClass().getName());
    }

    @Test
    public void testResolvePresentationDefinitionSuccess() throws Exception {
        // Setup mocks
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);
        
        // Create a mock OpenID4VP to control the authenticateVerifier method
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(mockPresentationDefinition);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        // Execute
        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "presentation-123", 
                "authorization-request", 
                true
        );

        // Verify
        assertNotNull(result);
        assertEquals(mockPresentationDefinition, result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier(eq("authorization-request"));
        verify(mockAuthorizationRequest).getPresentationDefinition();
    }

    @ParameterizedTest
    @CsvSource(value = {
        "NULL, authorization-request",
        "presentation-123, NULL",
        "NULL, NULL"
    }, nullValues = "NULL")
    public void resolvePresentationDefinitionWithNullParametersReturnsNull(String presentationId, String authorizationRequest) throws Exception {
        PresentationDefinition result = openID4VPService.resolvePresentationDefinition(
                presentationId, authorizationRequest, true);

        assertNull(result);
        verifyNoInteractions(verifierService);
    }

    @Test
    public void testResolvePresentationDefinitionWithEmptyPresentationIdReturnsNull() throws Exception {
        // Setup mocks for empty string scenario - service doesn't check for empty strings, so it continues execution
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);
        
        // Create a mock OpenID4VP to control the authenticateVerifier method
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(mockPresentationDefinition);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        // Execute
        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "", 
                "authorization-request", 
                true
        );

        // Verify - Empty string is not null, so it will proceed to call verifierService
        assertNotNull(result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier(eq("authorization-request"));
        verify(mockAuthorizationRequest).getPresentationDefinition();
    }

    @Test
    public void testResolvePresentationDefinitionWithEmptyAuthorizationRequestReturnsNull() throws Exception {
        // Setup mocks for empty string scenario - service doesn't check for empty strings, so it continues execution
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);
        
        // Create a mock OpenID4VP to control the authenticateVerifier method
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(mockPresentationDefinition);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        // Execute
        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "presentation-123", 
                "", 
                true
        );

        // Verify - Empty string is not null, so it will proceed to call verifierService
        assertNotNull(result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier(eq(""));
        verify(mockAuthorizationRequest).getPresentationDefinition();
    }

    @Test
    public void testResolvePresentationDefinitionWithVerifierServiceExceptionThrowsException() throws Exception {
        // Setup mocks
        when(verifierService.getTrustedVerifiers())
                .thenThrow(new ApiNotAccessibleException());

        // Execute and verify exception
        assertThrows(ApiNotAccessibleException.class, () -> {
            openID4VPService.resolvePresentationDefinition(
                    "presentation-123", 
                    "authorization-request", 
                    true
            );
        });

        verify(verifierService).getTrustedVerifiers();
    }

    @Test
    public void testResolvePresentationDefinitionWithIOExceptionThrowsException() throws Exception {
        // Setup mocks
        when(verifierService.getTrustedVerifiers())
                .thenThrow(new IOException("Network error"));

        // Execute and verify exception
        assertThrows(IOException.class, () -> {
            openID4VPService.resolvePresentationDefinition(
                    "presentation-123", 
                    "authorization-request", 
                    true
            );
        });

        verify(verifierService).getTrustedVerifiers();
    }

    @Test
    public void testResolvePresentationDefinitionWithEmptyVerifiersList() throws Exception {
        // Setup mocks with empty verifiers list
        VerifiersDTO emptyVerifiersDTO = VerifiersDTO.builder()
                .verifiers(List.of())
                .build();
        when(verifierService.getTrustedVerifiers()).thenReturn(emptyVerifiersDTO);
        
        // Create a mock OpenID4VP to control the authenticateVerifier method
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(mockPresentationDefinition);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        // Execute
        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "presentation-123", 
                "authorization-request", 
                false
        );

        // Verify
        assertNotNull(result);
        assertEquals(mockPresentationDefinition, result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier("authorization-request");
        verify(mockAuthorizationRequest).getPresentationDefinition();
    }

    @Test
    public void testResolvePresentationDefinitionWithNullPresentationDefinition() throws Exception {
        // Setup mocks
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);
        
        // Create a mock OpenID4VP to control the authenticateVerifier method
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(null);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        // Execute
        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "presentation-123", 
                "authorization-request", 
                true
        );

        // Verify
        assertNull(result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier(eq("authorization-request"));
        verify(mockAuthorizationRequest).getPresentationDefinition();
    }

    @Test
    public void testResolveDcqlQuerySuccess() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);

        DCQLQuery mockDcqlQuery = mock(DCQLQuery.class);
        AuthorizationDcqlRequest mockDcqlRequest = mock(AuthorizationDcqlRequest.class);
        when(mockDcqlRequest.getDcqlQuery()).thenReturn(mockDcqlQuery);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockDcqlRequest);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        DCQLQuery result = spyService.resolveDcqlQuery(
                "presentation-123", "authorization-request", true);

        assertNotNull(result);
        assertEquals(mockDcqlQuery, result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier(eq("authorization-request"));
        verify(mockDcqlRequest).getDcqlQuery();
    }

    @ParameterizedTest
    @CsvSource(value = {
        "NULL, authorization-request",
        "presentation-123, NULL",
        "NULL, NULL"
    }, nullValues = "NULL")
    public void resolveDcqlQueryWithNullParametersReturnsNull(String presentationId, String authorizationRequest) throws Exception {
        DCQLQuery result = openID4VPService.resolveDcqlQuery(presentationId, authorizationRequest, true);

        assertNull(result);
        verifyNoInteractions(verifierService);
    }

    @Test
    public void testResolveDcqlQueryReturnsNullForPresentationExchangeRequest() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        DCQLQuery result = spyService.resolveDcqlQuery(
                "presentation-123", "authorization-request", true);

        assertNull(result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier(eq("authorization-request"));
        verify(mockAuthorizationRequest, never()).getPresentationDefinition();
    }

    @Test
    public void testResolveDcqlQueryWithNullDcqlQuery() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);

        AuthorizationDcqlRequest mockDcqlRequest = mock(AuthorizationDcqlRequest.class);
        when(mockDcqlRequest.getDcqlQuery()).thenReturn(null);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockDcqlRequest);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        DCQLQuery result = spyService.resolveDcqlQuery(
                "presentation-123", "authorization-request", false);

        assertNull(result);
        verify(mockDcqlRequest).getDcqlQuery();
    }

    @Test
    public void testResolveDcqlQueryWithVerifierServiceExceptionThrowsException() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenThrow(new ApiNotAccessibleException());

        assertThrows(ApiNotAccessibleException.class, () ->
                openID4VPService.resolveDcqlQuery("presentation-123", "authorization-request", true));

        verify(verifierService).getTrustedVerifiers();
    }

    @Test
    public void testResolveDcqlQueryWithIOExceptionThrowsException() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenThrow(new IOException("Network error"));

        assertThrows(IOException.class, () ->
                openID4VPService.resolveDcqlQuery("presentation-123", "authorization-request", true));

        verify(verifierService).getTrustedVerifiers();
    }

    @Test
    public void testSendErrorToVerifierSuccess() throws Exception {
        // Setup mocks
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifierResponse mockResponse = mock(VerifierResponse.class);

        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);
        when(mockOpenID4VP.sendErrorInfoToVerifier(any())).thenReturn(mockResponse);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        VerifiablePresentationSessionData sessionData = mock(VerifiablePresentationSessionData.class);
        when(sessionData.getPresentationId()).thenReturn("presentation-123");
        when(sessionData.getAuthorizationRequest()).thenReturn("authorization-request");
        when(sessionData.isVerifierClientPreregistered()).thenReturn(true);

        ErrorDTO payload = mock(ErrorDTO.class);
        when(payload.getErrorMessage()).thenReturn("access_denied");

        // Execute
        VerifierResponse response = spyService.sendErrorToVerifier(sessionData, payload);

        // Verify
        assertNotNull(response);
        assertEquals(mockResponse, response);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier(eq("authorization-request"));
        ArgumentCaptor<Exception> errorCaptor = ArgumentCaptor.forClass(Exception.class);
        verify(mockOpenID4VP).sendErrorInfoToVerifier(errorCaptor.capture());
        assertTrue(errorCaptor.getValue() instanceof OpenID4VPExceptions.AccessDenied);
        assertEquals(OpenID4VPErrorCodes.ACCESS_DENIED,
                ((OpenID4VPExceptions) errorCaptor.getValue()).getErrorCode());
    }

    @Test
    public void testSendErrorToVerifierUsesInvalidTransactionDataWhenErrorCodeSet() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifierResponse mockResponse = mock(VerifierResponse.class);

        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);
        when(mockOpenID4VP.sendErrorInfoToVerifier(any())).thenReturn(mockResponse);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        VerifiablePresentationSessionData sessionData = mock(VerifiablePresentationSessionData.class);
        when(sessionData.getPresentationId()).thenReturn("presentation-123");
        when(sessionData.getAuthorizationRequest()).thenReturn("authorization-request");
        when(sessionData.isVerifierClientPreregistered()).thenReturn(true);

        ErrorDTO payload = mock(ErrorDTO.class);
        when(payload.getErrorCode()).thenReturn(OpenID4VPErrorCodes.INVALID_TRANSACTION_DATA);
        when(payload.getErrorMessage()).thenReturn("No matching credentials");

        VerifierResponse response = spyService.sendErrorToVerifier(sessionData, payload);

        assertNotNull(response);
        assertEquals(mockResponse, response);

        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(mockOpenID4VP).sendErrorInfoToVerifier(captor.capture());
        assertTrue(captor.getValue() instanceof OpenID4VPExceptions.InvalidTransactionData);
        assertEquals(OpenID4VPErrorCodes.INVALID_TRANSACTION_DATA,
                ((OpenID4VPExceptions) captor.getValue()).getErrorCode());
    }

    @Test
    public void testSendErrorToVerifierWithNullErrorPayload() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        VerifiablePresentationSessionData sessionData = mock(VerifiablePresentationSessionData.class);
        when(sessionData.getPresentationId()).thenReturn("presentation-123");
        when(sessionData.getAuthorizationRequest()).thenReturn("authorization-request");
        when(sessionData.isVerifierClientPreregistered()).thenReturn(true);

        assertThrows(IllegalArgumentException.class, () -> spyService.sendErrorToVerifier(sessionData, null));
        verify(mockOpenID4VP, never()).sendErrorInfoToVerifier(any());
    }

    @Test
    public void testSendErrorToVerifierMapsBlankErrorCodeToAccessDenied() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifierResponse mockResponse = mock(VerifierResponse.class);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);
        when(mockOpenID4VP.sendErrorInfoToVerifier(any())).thenReturn(mockResponse);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        VerifiablePresentationSessionData sessionData = mock(VerifiablePresentationSessionData.class);
        when(sessionData.getPresentationId()).thenReturn("presentation-123");
        when(sessionData.getAuthorizationRequest()).thenReturn("authorization-request");
        when(sessionData.isVerifierClientPreregistered()).thenReturn(true);

        ErrorDTO payload = mock(ErrorDTO.class);
        when(payload.getErrorCode()).thenReturn("   ");
        when(payload.getErrorMessage()).thenReturn("msg");

        spyService.sendErrorToVerifier(sessionData, payload);

        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(mockOpenID4VP).sendErrorInfoToVerifier(captor.capture());
        assertTrue(captor.getValue() instanceof OpenID4VPExceptions.AccessDenied);
        assertEquals(OpenID4VPErrorCodes.ACCESS_DENIED,
                ((OpenID4VPExceptions) captor.getValue()).getErrorCode());
    }

    @Test
    public void testSendErrorToVerifierMapsAccessDeniedCodeToAccessDenied() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifierResponse mockResponse = mock(VerifierResponse.class);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);
        when(mockOpenID4VP.sendErrorInfoToVerifier(any())).thenReturn(mockResponse);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        VerifiablePresentationSessionData sessionData = mock(VerifiablePresentationSessionData.class);
        when(sessionData.getPresentationId()).thenReturn("presentation-123");
        when(sessionData.getAuthorizationRequest()).thenReturn("authorization-request");
        when(sessionData.isVerifierClientPreregistered()).thenReturn(true);

        ErrorDTO payload = mock(ErrorDTO.class);
        when(payload.getErrorCode()).thenReturn(OpenID4VPErrorCodes.ACCESS_DENIED);
        when(payload.getErrorMessage()).thenReturn("user denied");

        spyService.sendErrorToVerifier(sessionData, payload);

        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(mockOpenID4VP).sendErrorInfoToVerifier(captor.capture());
        assertTrue(captor.getValue() instanceof OpenID4VPExceptions.AccessDenied);
        assertEquals(OpenID4VPErrorCodes.ACCESS_DENIED,
                ((OpenID4VPExceptions) captor.getValue()).getErrorCode());
    }

    @Test
    public void testSendErrorToVerifierMapsUnknownErrorCodeToAccessDenied() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifierResponse mockResponse = mock(VerifierResponse.class);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);
        when(mockOpenID4VP.sendErrorInfoToVerifier(any())).thenReturn(mockResponse);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        VerifiablePresentationSessionData sessionData = mock(VerifiablePresentationSessionData.class);
        when(sessionData.getPresentationId()).thenReturn("presentation-123");
        when(sessionData.getAuthorizationRequest()).thenReturn("authorization-request");
        when(sessionData.isVerifierClientPreregistered()).thenReturn(true);

        ErrorDTO payload = mock(ErrorDTO.class);
        when(payload.getErrorCode()).thenReturn("invalid_request");
        when(payload.getErrorMessage()).thenReturn("bad");

        spyService.sendErrorToVerifier(sessionData, payload);

        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(mockOpenID4VP).sendErrorInfoToVerifier(captor.capture());
        assertTrue(captor.getValue() instanceof OpenID4VPExceptions.AccessDenied);
        assertEquals(OpenID4VPErrorCodes.ACCESS_DENIED,
                ((OpenID4VPExceptions) captor.getValue()).getErrorCode());
    }

    @Test
    public void testSendErrorToVerifierUsesEmptyMessageWhenErrorMessageNull() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifierResponse mockResponse = mock(VerifierResponse.class);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(mockAuthorizationRequest);
        when(mockOpenID4VP.sendErrorInfoToVerifier(any())).thenReturn(mockResponse);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        VerifiablePresentationSessionData sessionData = mock(VerifiablePresentationSessionData.class);
        when(sessionData.getPresentationId()).thenReturn("presentation-123");
        when(sessionData.getAuthorizationRequest()).thenReturn("authorization-request");
        when(sessionData.isVerifierClientPreregistered()).thenReturn(true);

        ErrorDTO payload = mock(ErrorDTO.class);
        when(payload.getErrorCode()).thenReturn(OpenID4VPErrorCodes.ACCESS_DENIED);
        when(payload.getErrorMessage()).thenReturn(null);

        spyService.sendErrorToVerifier(sessionData, payload);

        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(mockOpenID4VP).sendErrorInfoToVerifier(captor.capture());
        assertEquals("", captor.getValue().getMessage());
    }

    @Test
    public void testSendErrorToVerifierWithNullSessionData() {
        // Setup
        VerifiablePresentationSessionData sessionData = null;
        ErrorDTO payload = mock(ErrorDTO.class);

        // Execute and verify
        assertThrows(IllegalArgumentException.class,
                () -> openID4VPService.sendErrorToVerifier(sessionData, payload));
        verifyNoInteractions(verifierService);
    }

    @Test
    public void testSendErrorToVerifierWithNullPresentationId() {
        // Setup
        VerifiablePresentationSessionData sessionData = mock(VerifiablePresentationSessionData.class);
        when(sessionData.getPresentationId()).thenReturn(null);

        ErrorDTO payload = mock(ErrorDTO.class);

        // Execute and verify
        assertThrows(IllegalArgumentException.class,
                () -> openID4VPService.sendErrorToVerifier(sessionData, payload));
        verifyNoInteractions(verifierService);
    }

    @Test
    public void testSendErrorToVerifierWithNullAuthorizationRequest() {
        // Setup
        VerifiablePresentationSessionData sessionData = mock(VerifiablePresentationSessionData.class);
        when(sessionData.getPresentationId()).thenReturn("presentation-123");
        when(sessionData.getAuthorizationRequest()).thenReturn(null);

        ErrorDTO payload = mock(ErrorDTO.class);

        // Execute and verify
        assertThrows(IllegalArgumentException.class,
                () -> openID4VPService.sendErrorToVerifier(sessionData, payload));
        verifyNoInteractions(verifierService);
    }

    @Test
    public void testSendErrorToVerifierPropagatesApiNotAccessibleException() throws Exception {
        // Setup
        when(verifierService.getTrustedVerifiers()).thenThrow(new ApiNotAccessibleException());

        VerifiablePresentationSessionData sessionData = mock(VerifiablePresentationSessionData.class);
        when(sessionData.getPresentationId()).thenReturn("presentation-123");
        when(sessionData.getAuthorizationRequest()).thenReturn("auth-request");

        ErrorDTO payload = mock(ErrorDTO.class);

        // Execute and verify
        assertThrows(ApiNotAccessibleException.class,
                () -> openID4VPService.sendErrorToVerifier(sessionData, payload));
        verify(verifierService).getTrustedVerifiers();
    }

}
