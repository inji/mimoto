package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.pkce.PkceSession;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.util.PkceUtil;
import jakarta.servlet.http.HttpSession;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;

/**
 * Creates and stores PKCE sessions.
 */
@Service
public class PkceSessionManager {

    public PkceSession createSession(String redirectUri) {
        if (StringUtils.isBlank(redirectUri)) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "redirectUri cannot be blank");
        }
        String codeVerifier = PkceUtil.generateValue();
        return PkceSession.builder()
                .state(PkceUtil.generateValue())
                .codeVerifier(codeVerifier)
                .codeChallenge(PkceUtil.s256Challenge(codeVerifier))
                .redirectUri(redirectUri)
                .build();
    }

    public PkceSession require(HttpSession httpSession, String state) {
        PkceSession session = find(httpSession, state);
        if (session == null) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "PKCE session not found");
        }
        return session;
    }

    public PkceSession find(HttpSession httpSession, String state) {
        if (httpSession == null || StringUtils.isBlank(state)) {
            return null;
        }
        return sessions(httpSession).get(state);
    }

    public void store(HttpSession httpSession, PkceSession pkceSession) {
        synchronized (httpSession) {
            Map<String, PkceSession> sessions = sessions(httpSession);
            sessions.put(pkceSession.getState(), pkceSession);
            httpSession.setAttribute(SessionKeys.PKCE_SESSION, sessions);
        }
    }

    public void remove(HttpSession httpSession, String state) {
        if (httpSession == null || StringUtils.isBlank(state)) {
            return;
        }
        synchronized (httpSession) {
            Map<String, PkceSession> sessions = sessions(httpSession);
            sessions.remove(state);
            httpSession.setAttribute(SessionKeys.PKCE_SESSION, sessions);
        }
    }

    public Map<String, String> authorizationCodeParams(HttpSession httpSession, String state, String code, String issuerId) {
        PkceSession pkceSession = require(httpSession, state);
        if (StringUtils.isBlank(pkceSession.getCodeVerifier()) || StringUtils.isBlank(pkceSession.getRedirectUri())) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "PKCE session is incomplete");
        }
        if (StringUtils.isBlank(code)) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "code cannot be blank");
        }
        if (StringUtils.isBlank(issuerId)) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "issuerId cannot be blank");
        }
        Map<String, String> params = new HashMap<>();
        params.put("code", code);
        params.put("code_verifier", pkceSession.getCodeVerifier());
        params.put("redirect_uri", pkceSession.getRedirectUri());
        params.put("grant_type", "authorization_code");
        params.put("issuer", issuerId);
        params.put("state", state);
        return params;
    }

    @SuppressWarnings("unchecked")
    private Map<String, PkceSession> sessions(HttpSession httpSession) {
        Map<String, PkceSession> sessions =
                (Map<String, PkceSession>) httpSession.getAttribute(SessionKeys.PKCE_SESSION);
        if (sessions == null) {
            return new HashMap<>();
        }
        return new HashMap<>(sessions);
    }
}
