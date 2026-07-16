package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@Slf4j
public class SessionManager {

    private final ObjectMapper objectMapper;

    public SessionManager(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public void setupSession(HttpServletRequest request, String provider, UserMetadataDTO userMetadata, String userId) {
        HttpSession session = request.getSession(true);
        session.setAttribute(SessionKeys.CLIENT_REGISTRATION_ID, provider);
        session.setAttribute(SessionKeys.USER_METADATA, userMetadata);
        session.setAttribute(SessionKeys.USER_ID, userId);
    }

    public void storePresentationSessionData(HttpSession httpSession, VerifiablePresentationSessionData sessionData, String walletId) {
        Map<String, VerifiablePresentationSessionData> presentations = getOrCreateSessionMap(httpSession, SessionKeys.PRESENTATIONS + "::" + walletId);

        // Adds the new presentation to the map if it is not already present
        presentations.computeIfAbsent(sessionData.getPresentationId(), id -> sessionData);

        // Store the updated presentations map in the session
        httpSession.setAttribute(SessionKeys.PRESENTATIONS + "::" + walletId, presentations);
    }

    /**
     * Retrieves the verifiable presentation session data from session for a given presentation
     * ID.
     *
     * @param httpSession    The HTTP session.
     * @param presentationId The presentation ID.
     * @return The verifiable presentation session data if found, null otherwise.
     */
    public VerifiablePresentationSessionData getPresentationSessionData(HttpSession httpSession, String walletId, String presentationId) {

        validateInputParameters(httpSession, walletId, presentationId);

        Map<String, VerifiablePresentationSessionData> presentations = (Map<String, VerifiablePresentationSessionData>) httpSession.getAttribute(SessionKeys.PRESENTATIONS + "::" + walletId);
        if (presentations == null || !presentations.containsKey(presentationId))
            throw new IllegalArgumentException("presentationId not found in session");
        return presentations.get(presentationId);
    }

    private void validateInputParameters(HttpSession httpSession, String walletId, String presentationId) {
        if (httpSession == null) {
            throw new IllegalArgumentException("HTTP session is invalid");
        }
        if (walletId == null || walletId.trim().isEmpty()) {
            throw new IllegalArgumentException("Wallet ID is invalid");
        }
        if (presentationId == null || presentationId.trim().isEmpty()) {
            throw new IllegalArgumentException("presentationId not found in session");
        }
    }

    /**
     * Stores the matching credentials response and filtered decrypted credentials in the session cache.
     *
     * @param httpSession                 The HTTP session.
     * @param walletId              The wallet ID.
     * @param existingSessionData The existing object in cache.
     * @param credentials                 The decrypted credentials to cache.
     */
    public void storeMatchingWalletCredentialsInPresentationSessionData(HttpSession httpSession, String walletId, VerifiablePresentationSessionData existingSessionData, List<DecryptedCredentialDTO> credentials) {
        VerifiablePresentationSessionData updatedSessionData = new VerifiablePresentationSessionData(
                existingSessionData.getPresentationId(),
                existingSessionData.getAuthorizationRequest(),
                existingSessionData.getCreatedAt(),
                existingSessionData.isVerifierClientPreregistered(),
                credentials,
                existingSessionData.isDcql());

        // Update the presentations map with the updated session data
        Map<String, VerifiablePresentationSessionData> presentations = (Map<String, VerifiablePresentationSessionData>) httpSession.getAttribute(SessionKeys.PRESENTATIONS + "::" + walletId);
        presentations.put(updatedSessionData.getPresentationId(), updatedSessionData);
        httpSession.setAttribute(SessionKeys.PRESENTATIONS  + "::" + walletId, presentations);
    }

    /**
     * Helper method to get or create a session map attribute for VerifiablePresentationSessionData objects.
     * This eliminates duplication in session map handling across store methods.
     *
     * @param httpSession The HTTP session.
     * @param key         The session attribute key.
     * @return The existing map or a new HashMap if none exists.
     */
    @SuppressWarnings("unchecked")
    private Map<String, VerifiablePresentationSessionData> getOrCreateSessionMap(HttpSession httpSession, String key) {
        Map<String, VerifiablePresentationSessionData> sessionMap = (Map<String, VerifiablePresentationSessionData>) httpSession.getAttribute(key);
        if (sessionMap == null) {
            sessionMap = new HashMap<>();
        }
        return sessionMap;
    }
}