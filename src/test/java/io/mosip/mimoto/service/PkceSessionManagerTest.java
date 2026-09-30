package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.pkce.PkceSession;
import io.mosip.mimoto.exception.InvalidRequestException;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PkceSessionManagerTest {

    private final PkceSessionManager pkceSessionManager = new PkceSessionManager();

    @Test
    public void should_createPkceValues_when_sessionIsCreated() {
        PkceSession session = pkceSessionManager.createSession("https://injiweb.example.com/redirect");

        assertEquals(43, session.getState().length());
        assertEquals(43, session.getCodeVerifier().length());
        assertTrue(session.getCodeVerifier().matches("^[A-Za-z0-9\\-._~]{43}$"));
        assertNotEquals(session.getState(), session.getCodeVerifier());
        assertEquals("https://injiweb.example.com/redirect", session.getRedirectUri());
        assertNotNull(session.getCodeChallenge());
    }

    @Test
    public void should_storeAndRemovePkceSession_when_httpSessionIsUsed() {
        MockHttpSession httpSession = new MockHttpSession();
        PkceSession session = pkceSessionManager.createSession("https://injiweb.example.com/redirect");

        pkceSessionManager.store(httpSession, session);

        assertNotNull(httpSession.getAttribute(SessionKeys.PKCE_SESSION));
        assertEquals(session.getCodeVerifier(), pkceSessionManager.find(httpSession, session.getState()).getCodeVerifier());

        pkceSessionManager.remove(httpSession, session.getState());
        assertNull(pkceSessionManager.find(httpSession, session.getState()));
    }

    @Test
    public void should_includeStoredPkceAndRedirectUri_when_authorizationCodeParamsAreBuilt() {
        MockHttpSession httpSession = new MockHttpSession();
        PkceSession session = pkceSessionManager.createSession("https://injiweb.example.com/redirect");
        pkceSessionManager.store(httpSession, session);

        java.util.Map<String, String> params = pkceSessionManager.authorizationCodeParams(
                httpSession, session.getState(), "auth-code", "LocalMockid");

        assertEquals("auth-code", params.get("code"));
        assertEquals(session.getCodeVerifier(), params.get("code_verifier"));
        assertEquals("https://injiweb.example.com/redirect", params.get("redirect_uri"));
        assertEquals("authorization_code", params.get("grant_type"));
        assertEquals("LocalMockid", params.get("issuer"));
        assertEquals(session.getState(), params.get("state"));
    }

    @Test
    public void should_throwInvalidRequest_when_issuerIdIsBlank() {
        MockHttpSession httpSession = new MockHttpSession();
        PkceSession session = pkceSessionManager.createSession("https://injiweb.example.com/redirect");
        pkceSessionManager.store(httpSession, session);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> pkceSessionManager.authorizationCodeParams(httpSession, session.getState(), "auth-code", " "));
        assertEquals("issuerId cannot be blank", exception.getErrorText());
    }

    @Test
    public void should_throwInvalidRequest_when_authorizationCodeIsBlank() {
        MockHttpSession httpSession = new MockHttpSession();
        PkceSession session = pkceSessionManager.createSession("https://injiweb.example.com/redirect");
        pkceSessionManager.store(httpSession, session);

        assertThrows(InvalidRequestException.class,
                () -> pkceSessionManager.authorizationCodeParams(httpSession, session.getState(), " ", "LocalMockid"));
    }

    @Test
    public void should_throwInvalidRequest_when_redirectUriIsBlank() {
        assertThrows(InvalidRequestException.class, () -> pkceSessionManager.createSession(" "));
    }
}
