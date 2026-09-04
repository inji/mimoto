package io.mosip.mimoto.service;

import com.nimbusds.jwt.SignedJWT;
import io.mosip.mimoto.dto.dpop.DpopIssuanceSession;
import io.mosip.mimoto.exception.InvalidRequestException;
import org.junit.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class DpopProofServiceTest {

    private final DpopProofService dpopProofService = new DpopProofService();

    @Test
    public void shouldUseFirstAdvertisedAlgorithmWhenAuthorizationServerPublishesAList() {
        assertEquals("RS256", dpopProofService.selectAlgorithm(
                List.of("RS256", "ES512", "EdDSA", "ES256K", "ES256", "ES384")));
        assertEquals("ES256", dpopProofService.selectAlgorithm(List.of("ES256", "RS256", "PS256")));
    }

    @Test
    public void shouldDefaultToEs256WhenAuthorizationServerOmitsDpopAlgs() {
        assertEquals("ES256", dpopProofService.selectAlgorithm(null));
        assertEquals("ES256", dpopProofService.selectAlgorithm(List.of()));
    }

    @Test
    public void shouldSkipAdvertisedAlgorithmsThatMimotoCannotSign() {
        assertEquals("RS256", dpopProofService.selectAlgorithm(List.of("ES256K", "RS256")));
    }

    @Test
    public void shouldRejectUnsupportedAlgorithmSet() {
        assertThrows(InvalidRequestException.class,
                () -> dpopProofService.selectAlgorithm(List.of("ES256K")));
    }

    @Test
    public void shouldStripQueryAndFragmentFromHtu() {
        assertEquals("https://as.example.com/v1/esignet/oauth/token",
                DpopProofService.normalizeHtu("https://as.example.com/v1/esignet/oauth/token?x=1#frag"));
    }

    @Test
    public void shouldCreateSessionAndSignProofWithNonceAndAth() throws Exception {
        DpopIssuanceSession session = dpopProofService.createSession(
                "oauth-state",
                "LocalMock",
                "RS256",
                "https://as.example.com/v1/esignet/oauth/token?x=1",
                "https://issuer.example/v1/certify/issuance");

        assertNotNull(session.getJkt());
        assertEquals("https://as.example.com/v1/esignet/oauth/token", session.getTokenHtu());
        assertEquals("https://issuer.example/v1/certify/issuance", session.getCredentialHtu());

        String proof = dpopProofService.createProof(session, session.getCredentialHtu(), "POST", "issuer-nonce", "access-token");
        SignedJWT jwt = SignedJWT.parse(proof);

        assertEquals("dpop+jwt", jwt.getHeader().getType().toString());
        assertEquals("RS256", jwt.getHeader().getAlgorithm().getName());
        assertNotNull(jwt.getHeader().getJWK());
        assertEquals("POST", jwt.getJWTClaimsSet().getStringClaim("htm"));
        assertEquals(session.getCredentialHtu(), jwt.getJWTClaimsSet().getStringClaim("htu"));
        assertEquals("issuer-nonce", jwt.getJWTClaimsSet().getStringClaim("nonce"));
        assertNotNull(jwt.getJWTClaimsSet().getStringClaim("ath"));
        assertNotEquals("access-token", jwt.getJWTClaimsSet().getStringClaim("ath"));
    }
}
