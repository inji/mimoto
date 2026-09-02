package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.DpopConstants;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.dpop.DpopIssuanceSession;
import io.mosip.mimoto.dto.dpop.IssuerAuthorizeRequest;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.util.AuthorizationUrlBuilder;
import io.mosip.mimoto.exception.DpopChallengeException;
import io.mosip.mimoto.exception.InvalidRequestException;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;

@Service
@Slf4j
public class DpopIssuanceSessionService {

    private final IssuersService issuersService;
    private final DpopProofService dpopProofService;

    public DpopIssuanceSessionService(IssuersService issuersService, DpopProofService dpopProofService) {
        this.issuersService = issuersService;
        this.dpopProofService = dpopProofService;
    }

    public String createAuthorizationUrl(HttpSession httpSession, String issuerId, String state,
                                         IssuerAuthorizeRequest request)
            throws Exception {
        if (request == null) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "authorization request is required");
        }
        CredentialIssuerConfiguration configuration = issuersService.getIssuerConfiguration(issuerId);
        DpopIssuanceSession issuanceSession = createIssuanceSession(httpSession, issuerId, state, configuration);
        IssuerDTO issuer = issuersService.getIssuerDetails(issuerId);
        if (configuration.getAuthorizationServerWellKnownResponse() == null
                || StringUtils.isBlank(configuration.getAuthorizationServerWellKnownResponse().getAuthorizationEndpoint())) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "authorization_endpoint is missing");
        }
        String authorizationEndpoint = configuration.getAuthorizationServerWellKnownResponse().getAuthorizationEndpoint();
        if (StringUtils.isBlank(issuer.getClient_id())) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "client_id is missing");
        }
        return AuthorizationUrlBuilder.build(
                authorizationEndpoint,
                issuer.getClient_id(),
                request.getRedirectUri(),
                request.getScope(),
                request.getResponseType(),
                state,
                request.getCodeChallenge(),
                request.getCodeChallengeMethod(),
                request.getUiLocales(),
                issuanceSession.getJkt());
    }

    private DpopIssuanceSession createIssuanceSession(HttpSession httpSession, String issuerId, String state,
                                                      CredentialIssuerConfiguration configuration) throws Exception {
        if (httpSession == null) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "HTTP session is required for DPoP issuance");
        }
        if (StringUtils.isBlank(state)) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "state cannot be blank");
        }
        String alg = dpopProofService.selectAlgorithm(
                configuration.getAuthorizationServerWellKnownResponse().getDpopSigningAlgValuesSupported());
        DpopIssuanceSession issuanceSession = dpopProofService.createSession(
                state,
                issuerId,
                alg,
                configuration.getAuthorizationServerWellKnownResponse().getTokenEndpoint(),
                configuration.getCredentialEndPoint());
        store(httpSession, issuanceSession);
        log.info("Created BFF DPoP issuance session for issuer {} alg {}", issuerId, alg);
        return issuanceSession;
    }

    public DpopIssuanceSession require(HttpSession httpSession, String state) {
        DpopIssuanceSession session = find(httpSession, state);
        if (session == null) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "DPoP issuance session not found");
        }
        return session;
    }

    public DpopIssuanceSession find(HttpSession httpSession, String state) {
        if (httpSession == null || StringUtils.isBlank(state)) {
            return null;
        }
        Map<String, DpopIssuanceSession> sessions = sessions(httpSession);
        return sessions.get(state);
    }

    public void store(HttpSession httpSession, DpopIssuanceSession issuanceSession) {
        Map<String, DpopIssuanceSession> sessions = sessions(httpSession);
        sessions.put(issuanceSession.getState(), issuanceSession);
        httpSession.setAttribute(SessionKeys.DPOP_ISSUANCE, sessions);
    }

    public void remove(HttpSession httpSession, String state) {
        if (httpSession == null || StringUtils.isBlank(state)) {
            return;
        }
        Map<String, DpopIssuanceSession> sessions = sessions(httpSession);
        sessions.remove(state);
        httpSession.setAttribute(SessionKeys.DPOP_ISSUANCE, sessions);
    }

    public TokenResponseDTO tokenFromSession(HttpSession httpSession, String state) {
        DpopIssuanceSession session = find(httpSession, state);
        if (session == null || StringUtils.isBlank(session.getAccessToken())) {
            return null;
        }
        TokenResponseDTO token = new TokenResponseDTO();
        token.setAccess_token(session.getAccessToken());
        token.setToken_type(StringUtils.isBlank(session.getTokenType())
                ? DpopConstants.DPOP_TOKEN_TYPE
                : session.getTokenType());
        token.setC_nonce(session.getCNonce());
        return token;
    }

    public String credentialProof(HttpSession httpSession, String state) {
        DpopIssuanceSession session = find(httpSession, state);
        if (session == null || StringUtils.isBlank(session.getAccessToken())) {
            return null;
        }
        if (!DpopConstants.DPOP_TOKEN_TYPE.equalsIgnoreCase(session.getTokenType())) {
            return null;
        }
        return dpopProofService.createProof(
                session, session.getCredentialHtu(), "POST", session.getIssuerDpopNonce(), session.getAccessToken());
    }

    public String retryCredentialProof(HttpSession httpSession, String state, DpopChallengeException challenge) {
        String nonce = challenge.getResponseHeaders() != null
                ? challenge.getResponseHeaders().getFirst(DpopConstants.DPOP_NONCE_HEADER)
                : null;
        DpopIssuanceSession session = require(httpSession, state);
        session.setIssuerDpopNonce(nonce);
        store(httpSession, session);
        return dpopProofService.createProof(
                session, session.getCredentialHtu(), "POST", nonce, session.getAccessToken());
    }

    @SuppressWarnings("unchecked")
    private Map<String, DpopIssuanceSession> sessions(HttpSession httpSession) {
        Map<String, DpopIssuanceSession> sessions =
                (Map<String, DpopIssuanceSession>) httpSession.getAttribute(SessionKeys.DPOP_ISSUANCE);
        if (sessions == null) {
            return new HashMap<>();
        }
        return new HashMap<>(sessions);
    }
}
