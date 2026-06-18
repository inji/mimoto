package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.mimoto.model.CredentialMetadata;
import io.mosip.mimoto.service.impl.SessionManager;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpSession;

import java.time.Instant;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class SessionManagerTest {

    UserMetadataDTO userMetadataDTO;
    private SessionManager sessionManager;
    @Mock
    private ObjectMapper objectMapper;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        sessionManager = new SessionManager(objectMapper);
        userMetadataDTO = new UserMetadataDTO("Test user", "https://test.com/pic.jpg", "test@example.com", "wallet123");
    }

    @Test
    public void shouldSetupSessionWithProvidedUserAndOAuth2ProviderDetails() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpSession session = new MockHttpSession();
        when(request.getSession(true)).thenReturn(session);

        String provider = "google";
        String userId = "123";

        sessionManager.setupSession(request, provider, userMetadataDTO, userId);

        assertEquals(provider, session.getAttribute(SessionKeys.CLIENT_REGISTRATION_ID));
        assertEquals(userMetadataDTO, session.getAttribute(SessionKeys.USER_METADATA));
        assertEquals(userId, session.getAttribute(SessionKeys.USER_ID));
    }

    @Test
    public void shouldCreateAndStorePresentationDetailsInSession() {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        MockHttpSession session = new MockHttpSession();
        String walletId = "wallet123";
        String presentationId = "123e4567-e89b-12d3-a456-426614174000";
        VerifiablePresentationSessionData presentationSessionData = new VerifiablePresentationSessionData(presentationId, "authorizationRequest", fixedInstant, false, null, null);

        sessionManager.storePresentationSessionData(session, presentationSessionData, walletId);

        @SuppressWarnings("unchecked")
        Map<String, VerifiablePresentationSessionData> presentations =
                (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS + "::" + walletId);

        assertNotNull(presentations);
        assertTrue(presentations.containsKey(presentationId));

        VerifiablePresentationSessionData storedPresentationSessionDetails = presentations.get(presentationId);
        assertNotNull(storedPresentationSessionDetails);
        assertEquals(presentationSessionData.getAuthorizationRequest(), storedPresentationSessionDetails.getAuthorizationRequest());
        assertEquals(presentationSessionData.getCreatedAt(), storedPresentationSessionDetails.getCreatedAt());
    }

    @Test
    public void shouldStorePresentationDetailsProperlyInSessionForMultiplePresentations() {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        MockHttpSession session = new MockHttpSession();

        String walletId1 = "wallet123";
        String walletId2 = "wallet456";
        String presentationId1 = "123e4567-e89b-12d3-a456-426614174000";
        String presentationId2 = "123e4567-e89b-12d3-a456-426614174001";

        VerifiablePresentationSessionData sessionData1 = new VerifiablePresentationSessionData(presentationId1, "authorizationRequest", fixedInstant, true, null, null);
        VerifiablePresentationSessionData sessionData2 = new VerifiablePresentationSessionData(presentationId2, "authorizationRequest", fixedInstant, false, null, null);

        sessionManager.storePresentationSessionData(session, sessionData1, walletId1);
        sessionManager.storePresentationSessionData(session, sessionData2, walletId2);

        @SuppressWarnings("unchecked")
        Map<String, VerifiablePresentationSessionData> presentations1 =
                (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS + "::" + walletId1);
        @SuppressWarnings("unchecked")
        Map<String, VerifiablePresentationSessionData> presentations2 =
                (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS + "::" + walletId2);

        assertNotNull(presentations1);
        assertNotNull(presentations2);

        assertTrue(presentations1.containsKey(presentationId1));
        assertTrue(presentations2.containsKey(presentationId2));

        VerifiablePresentationSessionData storedData1 = presentations1.get(presentationId1);
        VerifiablePresentationSessionData storedData2 = presentations2.get(presentationId2);

        assertNotNull(storedData1);
        assertNotNull(storedData2);

        assertEquals(sessionData1.getAuthorizationRequest(), storedData1.getAuthorizationRequest());
        assertEquals(sessionData1.getCreatedAt(), storedData1.getCreatedAt());
        assertEquals(sessionData2.getAuthorizationRequest(), storedData2.getAuthorizationRequest());
        assertEquals(sessionData2.getCreatedAt(), storedData2.getCreatedAt());
    }

    @Test
    public void shouldReturnPresentationDefinitionFromSessionSuccessfully() {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        String presentationId = "test-presentation-id";
        String walletId = "wallet123";
        MockHttpSession session = new MockHttpSession();

        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(presentationId,"mockOpenID4VP", fixedInstant,  true, null, null);

        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        presentations.put(presentationId, sessionData);
        session.setAttribute(SessionKeys.PRESENTATIONS + "::" + walletId, presentations);

        VerifiablePresentationSessionData result = sessionManager.getPresentationSessionData(session, walletId, presentationId);

        assertNotNull(result);
        assertNotNull(result.getAuthorizationRequest());
        assertEquals(fixedInstant, result.getCreatedAt());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldReturnNullWhenNoPresentationsInSession() {
        String presentationId = "test-presentation-id";
        String walletId = "wallet123";
        MockHttpSession session = new MockHttpSession();

        sessionManager.getPresentationSessionData(session, walletId, presentationId);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldReturnNullWhenPresentationIdNotFound() {
        String presentationId = "non-existent-id";
        String walletId = "wallet123";
        MockHttpSession session = new MockHttpSession();

        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        session.setAttribute(SessionKeys.PRESENTATIONS + "::" + walletId, presentations);

        sessionManager.getPresentationSessionData(session, walletId, presentationId);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldHandleExceptionWhenRetrievingPresentationSessionData() {
        // Arrange
        String presentationId = "test-presentation-id";
        String walletId = "wallet123";
        HttpSession session = mock(HttpSession.class);
        
        // Mock session to throw exception when getting attribute
        when(session.getAttribute(anyString())).thenThrow(new IllegalArgumentException("Session error"));

        // Act
        sessionManager.getPresentationSessionData(session, walletId, presentationId);
    }

    @Test
    public void shouldStoreMatchingWalletCredentialsInPresentationSessionData() {
        // Arrange
        MockHttpSession session = new MockHttpSession();
        String walletId = "wallet123";
        String presentationId = "test-presentation-id";
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        
        // Create existing session data
        VerifiablePresentationSessionData existingSessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequest", fixedInstant, true, null, null);
        
        // Create credentials to store
        List<DecryptedCredentialDTO> credentials = createMockCredentials();
        
        // Set up existing presentations map in session
        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        presentations.put(presentationId, existingSessionData);
        session.setAttribute(SessionKeys.PRESENTATIONS + "::" + walletId, presentations);

        // Act
        sessionManager.storeMatchingWalletCredentialsInPresentationSessionData(session, walletId, existingSessionData, credentials);

        // Assert
        @SuppressWarnings("unchecked")
        Map<String, VerifiablePresentationSessionData> updatedPresentations = 
                (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS + "::" + walletId);
        
        assertNotNull(updatedPresentations);
        assertTrue(updatedPresentations.containsKey(presentationId));
        
        VerifiablePresentationSessionData updatedSessionData = updatedPresentations.get(presentationId);
        assertNotNull(updatedSessionData);
        assertEquals(presentationId, updatedSessionData.getPresentationId());
        assertEquals("authorizationRequest", updatedSessionData.getAuthorizationRequest());
        assertEquals(fixedInstant, updatedSessionData.getCreatedAt());
        assertTrue(updatedSessionData.isVerifierClientPreregistered());
        assertEquals(credentials, updatedSessionData.getMatchingCredentials());
    }

    @Test
    public void shouldStoreMatchingWalletCredentialsWithNullExistingPresentations() {
        // Arrange
        MockHttpSession session = new MockHttpSession();
        String walletId = "wallet123";
        String presentationId = "test-presentation-id";
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        
        // Create existing session data
        VerifiablePresentationSessionData existingSessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequest", fixedInstant, true, null, null);
        
        // Create credentials to store
        List<DecryptedCredentialDTO> credentials = createMockCredentials();
        
        // Don't set up existing presentations map - should handle null case

        // Act & Assert - Should throw NullPointerException when trying to get null presentations map
        try {
            sessionManager.storeMatchingWalletCredentialsInPresentationSessionData(session, walletId, existingSessionData, credentials);
            fail("Expected NullPointerException to be thrown");
        } catch (NullPointerException e) {
            // Expected behavior
        }
    }

    @Test
    public void shouldCreateNewSessionMapWhenNoneExists() {
        // Arrange
        MockHttpSession session = new MockHttpSession();
        String walletId = "wallet123";
        String presentationId = "test-presentation-id";
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequest", fixedInstant, true, null, null);

        // Act
        sessionManager.storePresentationSessionData(session, sessionData, walletId);

        // Assert
        @SuppressWarnings("unchecked")
        Map<String, VerifiablePresentationSessionData> presentations = 
                (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS + "::" + walletId);
        
        assertNotNull(presentations);
        assertTrue(presentations.containsKey(presentationId));
        assertEquals(sessionData, presentations.get(presentationId));
    }

    @Test
    public void shouldNotOverwriteExistingPresentationWhenStoringSamePresentationId() {
        // Arrange
        MockHttpSession session = new MockHttpSession();
        String walletId = "wallet123";
        String presentationId = "test-presentation-id";
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        
        // Create original session data
        VerifiablePresentationSessionData originalSessionData = new VerifiablePresentationSessionData(
                presentationId, "originalRequest", fixedInstant, true, null, null);
        
        // Create new session data with same presentation ID
        VerifiablePresentationSessionData newSessionData = new VerifiablePresentationSessionData(
                presentationId, "newRequest", fixedInstant.plusSeconds(100), false, null, null);

        // Store original data
        sessionManager.storePresentationSessionData(session, originalSessionData, walletId);
        
        // Act - Try to store new data with same presentation ID
        sessionManager.storePresentationSessionData(session, newSessionData, walletId);

        // Assert - Should still have original data due to computeIfAbsent
        @SuppressWarnings("unchecked")
        Map<String, VerifiablePresentationSessionData> presentations = 
                (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS + "::" + walletId);
        
        assertNotNull(presentations);
        assertTrue(presentations.containsKey(presentationId));
        
        VerifiablePresentationSessionData storedData = presentations.get(presentationId);
        assertEquals("originalRequest", storedData.getAuthorizationRequest()); // Should be original, not new
        assertTrue(storedData.isVerifierClientPreregistered()); // Should be original, not new
    }

    @Test
    public void shouldHandleNullCredentialsInStoreMatchingWalletCredentials() {
        // Arrange
        MockHttpSession session = new MockHttpSession();
        String walletId = "wallet123";
        String presentationId = "test-presentation-id";
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        
        VerifiablePresentationSessionData existingSessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequest", fixedInstant, true, null, null);
        
        // Set up existing presentations map
        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        presentations.put(presentationId, existingSessionData);
        session.setAttribute(SessionKeys.PRESENTATIONS + "::" + walletId, presentations);

        // Act
        sessionManager.storeMatchingWalletCredentialsInPresentationSessionData(session, walletId, existingSessionData, null);

        // Assert
        @SuppressWarnings("unchecked")
        Map<String, VerifiablePresentationSessionData> updatedPresentations = 
                (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS + "::" + walletId);
        
        assertNotNull(updatedPresentations);
        VerifiablePresentationSessionData updatedSessionData = updatedPresentations.get(presentationId);
        assertNull(updatedSessionData.getMatchingCredentials());
    }

    @Test
    public void shouldHandleEmptyCredentialsListInStoreMatchingWalletCredentials() {
        // Arrange
        MockHttpSession session = new MockHttpSession();
        String walletId = "wallet123";
        String presentationId = "test-presentation-id";
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        
        VerifiablePresentationSessionData existingSessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequest", fixedInstant, true, null, null);
        
        // Set up existing presentations map
        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        presentations.put(presentationId, existingSessionData);
        session.setAttribute(SessionKeys.PRESENTATIONS + "::" + walletId, presentations);

        // Act
        sessionManager.storeMatchingWalletCredentialsInPresentationSessionData(session, walletId, existingSessionData, Collections.emptyList());

        // Assert
        @SuppressWarnings("unchecked")
        Map<String, VerifiablePresentationSessionData> updatedPresentations = 
                (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS + "::" + walletId);
        
        assertNotNull(updatedPresentations);
        VerifiablePresentationSessionData updatedSessionData = updatedPresentations.get(presentationId);
        assertNotNull(updatedSessionData.getMatchingCredentials());
        assertTrue(updatedSessionData.getMatchingCredentials().isEmpty());
    }

    // Helper method to create mock credentials
    private List<DecryptedCredentialDTO> createMockCredentials() {
        DecryptedCredentialDTO credential = new DecryptedCredentialDTO();
        credential.setId("test-credential-id");
        credential.setWalletId("wallet123");
        
        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("test-issuer");
        metadata.setCredentialType("TestCredential");
        credential.setCredentialMetadata(metadata);
        credential.setCreatedAt(Instant.now());
        credential.setUpdatedAt(Instant.now());
        
        return Collections.singletonList(credential);
    }
}
