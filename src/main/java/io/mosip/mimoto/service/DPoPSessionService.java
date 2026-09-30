package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.dpop.DPoPSession;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.AuthorizationServerWellKnownResponse;
import io.mosip.mimoto.exception.InvalidRequestException;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;

@Service
@Slf4j
public class DPoPSessionService {

    private final DPoPManager dPoPManager;

    public DPoPSessionService(DPoPManager dPoPManager) {
        this.dPoPManager = dPoPManager;
    }

    public DPoPSession createSession(String state, AuthorizationServerWellKnownResponse authorizationServer) {
        if (StringUtils.isBlank(state)) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "state cannot be blank");
        }
        if (authorizationServer == null || StringUtils.isBlank(authorizationServer.getTokenEndpoint())) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "token_endpoint is missing");
        }
        String alg = dPoPManager.selectAlgorithm(authorizationServer.getDPoPSigningAlgValuesSupported());
        DPoPSession dPoPSession = dPoPManager.createSession(state, alg, authorizationServer.getTokenEndpoint());
        log.info("Created DPoP session alg {}", alg);
        return dPoPSession;
    }

    public DPoPSession require(HttpSession httpSession, String state) {
        DPoPSession session = find(httpSession, state);
        if (session == null) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "DPoP session not found");
        }
        return session;
    }

    public DPoPSession find(HttpSession httpSession, String state) {
        if (httpSession == null || StringUtils.isBlank(state)) {
            return null;
        }
        Map<String, DPoPSession> sessions = sessions(httpSession);
        return sessions.get(state);
    }

    public void store(HttpSession httpSession, DPoPSession dPoPSession) {
        synchronized (httpSession) {
            Map<String, DPoPSession> sessions = sessions(httpSession);
            sessions.put(dPoPSession.getState(), dPoPSession);
            httpSession.setAttribute(SessionKeys.DPOP_SESSION, sessions);
        }
    }

    public void remove(HttpSession httpSession, String state) {
        if (httpSession == null || StringUtils.isBlank(state)) {
            return;
        }
        synchronized (httpSession) {
            Map<String, DPoPSession> sessions = sessions(httpSession);
            sessions.remove(state);
            httpSession.setAttribute(SessionKeys.DPOP_SESSION, sessions);
        }
    }

    public String credentialProof(HttpSession httpSession, String state, TokenResponseDTO token,
                                  String credentialEndpoint) {
        DPoPSession session = find(httpSession, state);
        if (session == null || token == null || StringUtils.isBlank(token.getAccess_token())) {
            return null;
        }
        return dPoPManager.generateCredentialProof(session, credentialEndpoint, token.getAccess_token());
    }

    public String retryCredentialProof(HttpSession httpSession, String state, TokenResponseDTO token,
                                       String nonce, String credentialEndpoint) {
        DPoPSession session = require(httpSession, state);
        String proof = dPoPManager.generateCredentialProof(
                session, credentialEndpoint, token.getAccess_token(), nonce);
        store(httpSession, session);
        return proof;
    }

    @SuppressWarnings("unchecked")
    private Map<String, DPoPSession> sessions(HttpSession httpSession) {
        Map<String, DPoPSession> sessions =
                (Map<String, DPoPSession>) httpSession.getAttribute(SessionKeys.DPOP_SESSION);
        if (sessions == null) {
            return new HashMap<>();
        }
        return new HashMap<>(sessions);
    }
}
