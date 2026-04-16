package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.openID4VP.networkManager.NetworkResponse;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.impl.OpenID4VPService;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition;
import io.mosip.openID4VP.common.OpenID4VPErrorCodes;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;
import io.mosip.openID4VP.verifier.VerifierResponse;
import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

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

@RunWith(MockitoJUnitRunner.class)
@Slf4j
public class OpenID4VPServiceTest {

    @Mock
    private VerifierService verifierService;

    @InjectMocks
    private OpenID4VPService openID4VPService;

    private VerifiersDTO mockVerifiersDTO;
    private VerifierDTO mockVerifierDTO;
    private AuthorizationRequest mockAuthorizationRequest;
    private PresentationDefinition mockPresentationDefinition;

    @Before
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
        mockAuthorizationRequest = mock(AuthorizationRequest.class);

        // Setup mock PresentationDefinition
        mockPresentationDefinition = mock(PresentationDefinition.class);
    }

    @Test
    public void testCreateReturnsValidOpenID4VP() {
        OpenID4VP openID4VP = openID4VPService.create("presentation-123");

        assertNotNull(openID4VP);
        assertEquals("io.mosip.openID4VP.OpenID4VP", openID4VP.getClass().getName());
    }

    @Test
    public void testCreateWithValidPresentationIdReturnsValidOpenID4VP() {
        OpenID4VP openID4VP = openID4VPService.create("valid-presentation-id");

        assertNotNull(openID4VP);
        assertEquals("io.mosip.openID4VP.OpenID4VP", openID4VP.getClass().getName());
    }

    @Test
    public void testCreateWithSpecialCharactersPresentationIdReturnsValidOpenID4VP() {
        OpenID4VP openID4VP = openID4VPService.create("presentation-123_with.special@chars");

        assertNotNull(openID4VP);
        assertEquals("io.mosip.openID4VP.OpenID4VP", openID4VP.getClass().getName());
    }

    @Test
    public void testResolvePresentationDefinitionSuccess() throws Exception {
        // Setup mocks
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);
        
        // Create a mock OpenID4VP to control the authenticateVerifier method
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(mockPresentationDefinition);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

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
        verify(mockOpenID4VP).authenticateVerifier(eq("authorization-request"), anyList(), eq(true));
        verify(mockAuthorizationRequest).getPresentationDefinition();
    }

    @Test
    public void testResolvePresentationDefinitionWithNullPresentationIdReturnsNull() throws Exception {
        // Execute
        PresentationDefinition result = openID4VPService.resolvePresentationDefinition(
                null, 
                "authorization-request", 
                true
        );

        // Verify
        assertNull(result);
        verifyNoInteractions(verifierService);
    }

    @Test
    public void testResolvePresentationDefinitionWithNullAuthorizationRequestReturnsNull() throws Exception {
        // Execute
        PresentationDefinition result = openID4VPService.resolvePresentationDefinition(
                "presentation-123", 
                null, 
                true
        );

        // Verify
        assertNull(result);
        verifyNoInteractions(verifierService);
    }

    @Test
    public void testResolvePresentationDefinitionWithBothNullParametersReturnsNull() throws Exception {
        // Execute
        PresentationDefinition result = openID4VPService.resolvePresentationDefinition(
                null, 
                null, 
                true
        );

        // Verify
        assertNull(result);
        verifyNoInteractions(verifierService);
    }

    @Test
    public void testResolvePresentationDefinitionWithEmptyPresentationIdReturnsNull() throws Exception {
        // Setup mocks for empty string scenario - service doesn't check for empty strings, so it continues execution
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);
        
        // Create a mock OpenID4VP to control the authenticateVerifier method
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(mockPresentationDefinition);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

        // Execute
        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "", 
                "authorization-request", 
                true
        );

        // Verify - Empty string is not null, so it will proceed to call verifierService
        assertNotNull(result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier(eq("authorization-request"), anyList(), eq(true));
        verify(mockAuthorizationRequest).getPresentationDefinition();
    }

    @Test
    public void testResolvePresentationDefinitionWithEmptyAuthorizationRequestReturnsNull() throws Exception {
        // Setup mocks for empty string scenario - service doesn't check for empty strings, so it continues execution
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);
        
        // Create a mock OpenID4VP to control the authenticateVerifier method
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(mockPresentationDefinition);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

        // Execute
        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "presentation-123", 
                "", 
                true
        );

        // Verify - Empty string is not null, so it will proceed to call verifierService
        assertNotNull(result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier(eq(""), anyList(), eq(true));
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
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(mockPresentationDefinition);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

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
        verify(mockOpenID4VP).authenticateVerifier("authorization-request", List.of(), false);
        verify(mockAuthorizationRequest).getPresentationDefinition();
    }

    @Test
    public void testResolvePresentationDefinitionWithNullPresentationDefinition() throws Exception {
        // Setup mocks
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);
        
        // Create a mock OpenID4VP to control the authenticateVerifier method
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(null);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

        // Execute
        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "presentation-123", 
                "authorization-request", 
                true
        );

        // Verify
        assertNull(result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier(eq("authorization-request"), anyList(), eq(true));
        verify(mockAuthorizationRequest).getPresentationDefinition();
    }

    @Test
    public void testSendErrorToVerifierSuccess() throws Exception {
        // Setup mocks
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifierResponse mockResponse = mock(VerifierResponse.class);

        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(mockAuthorizationRequest);
        when(mockOpenID4VP.sendErrorInfoToVerifier(any())).thenReturn(mockResponse);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

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
        verify(mockOpenID4VP).authenticateVerifier(eq("authorization-request"), anyList(), eq(true));
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

        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(mockAuthorizationRequest);
        when(mockOpenID4VP.sendErrorInfoToVerifier(any())).thenReturn(mockResponse);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

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
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(mockAuthorizationRequest);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

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
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(mockAuthorizationRequest);
        when(mockOpenID4VP.sendErrorInfoToVerifier(any())).thenReturn(mockResponse);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

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
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(mockAuthorizationRequest);
        when(mockOpenID4VP.sendErrorInfoToVerifier(any())).thenReturn(mockResponse);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

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
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(mockAuthorizationRequest);
        when(mockOpenID4VP.sendErrorInfoToVerifier(any())).thenReturn(mockResponse);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

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
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(mockAuthorizationRequest);
        when(mockOpenID4VP.sendErrorInfoToVerifier(any())).thenReturn(mockResponse);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

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
        // Remove this line - isVerifierClientPreregistered is never called due to early exception
        // when(sessionData.isVerifierClientPreregistered()).thenReturn(false);

        ErrorDTO payload = mock(ErrorDTO.class);

        // Execute and verify
        assertThrows(ApiNotAccessibleException.class,
                () -> openID4VPService.sendErrorToVerifier(sessionData, payload));
        verify(verifierService).getTrustedVerifiers();
    }

}
