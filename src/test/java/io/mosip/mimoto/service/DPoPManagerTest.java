package io.mosip.mimoto.service;

import com.nimbusds.jwt.SignedJWT;
import io.mosip.mimoto.constant.DPoPConstants;
import io.mosip.mimoto.dto.dpop.DPoPSession;
import io.mosip.mimoto.exception.InvalidRequestException;
import org.junit.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class DPoPManagerTest {

    private final DPoPManager dPoPManager = new DPoPManager();

    @Test
    public void should_selectFirstSupportedAlgorithm_when_authorizationServerPublishesAlgList() {
        assertEquals("RS256", dPoPManager.selectAlgorithm(
                List.of("RS256", "ES512", "EdDSA", "ES256K", "ES256", "ES384")));
        assertEquals("ES256", dPoPManager.selectAlgorithm(List.of("ES256", "RS256", "PS256")));
    }

    @Test
    public void should_defaultToEs256_when_authorizationServerOmitsDPoPAlgs() {
        assertEquals("ES256", dPoPManager.selectAlgorithm(null));
        assertEquals("ES256", dPoPManager.selectAlgorithm(List.of()));
    }

    @Test
    public void should_skipUnsupportedAlgs_when_selectingDPoPAlgorithm() {
        assertEquals("RS256", dPoPManager.selectAlgorithm(List.of("ES256K", "RS256")));
    }

    @Test
    public void should_throwInvalidRequest_when_noSupportedDPoPAlgIsAdvertised() {
        assertThrows(InvalidRequestException.class,
                () -> dPoPManager.selectAlgorithm(List.of("ES256K")));
    }

    @Test
    public void should_stripQueryAndFragment_when_htuIsNormalized() {
        assertEquals("https://as.example.com/v1/esignet/oauth/token",
                DPoPManager.normalizeHtu("https://as.example.com/v1/esignet/oauth/token?x=1#frag"));
    }

    @Test
    public void should_includeNonceAndAth_when_dPoPProofIsGenerated() throws Exception {
        DPoPSession session = dPoPManager.createSession(
                "oauth-state",
                "RS256",
                "https://as.example.com/v1/esignet/oauth/token?x=1");

        assertNotNull(dPoPManager.jwkThumbprint(session));
        assertEquals("https://as.example.com/v1/esignet/oauth/token", session.getTokenHtu());

        String credentialHtu = "https://issuer.example/credential";
        String proof = dPoPManager.generateCredentialProof(session, credentialHtu, "access-token", "issuer-nonce");
        SignedJWT jwt = SignedJWT.parse(proof);

        assertEquals("dpop+jwt", jwt.getHeader().getType().toString());
        assertEquals("RS256", jwt.getHeader().getAlgorithm().getName());
        assertNotNull(jwt.getHeader().getJWK());
        assertEquals(DPoPConstants.HTTP_METHOD_POST, jwt.getJWTClaimsSet().getStringClaim("htm"));
        assertEquals(credentialHtu, jwt.getJWTClaimsSet().getStringClaim("htu"));
        assertEquals("issuer-nonce", jwt.getJWTClaimsSet().getStringClaim("nonce"));
        assertNotNull(jwt.getJWTClaimsSet().getStringClaim("ath"));
        assertNotEquals("access-token", jwt.getJWTClaimsSet().getStringClaim("ath"));
        assertEquals("issuer-nonce", session.getIssuerDPoPNonce());
    }

    @Test
    public void should_omitAth_when_tokenProofIsGenerated() throws Exception {
        DPoPSession session = dPoPManager.createSession(
                "oauth-state",
                "RS256",
                "https://as.example.com/v1/esignet/oauth/token?x=1");

        String proof = dPoPManager.generateTokenProof(session);
        SignedJWT jwt = SignedJWT.parse(proof);

        assertEquals(DPoPConstants.HTTP_METHOD_POST, jwt.getJWTClaimsSet().getStringClaim("htm"));
        assertEquals(session.getTokenHtu(), jwt.getJWTClaimsSet().getStringClaim("htu"));
        assertNull(jwt.getJWTClaimsSet().getStringClaim("ath"));
        assertNull(jwt.getJWTClaimsSet().getStringClaim("nonce"));
    }
}
