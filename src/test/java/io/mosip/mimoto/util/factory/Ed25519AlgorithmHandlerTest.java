package io.mosip.mimoto.util.factory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64URL;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;

import static org.junit.Assert.*;

/**
 * Test cases for ED25519AlgorithmHandler.
 */
public class Ed25519AlgorithmHandlerTest {

    private final Ed25519AlgorithmHandler handler = new Ed25519AlgorithmHandler();

    @Test
    public void shouldGenerateKeyPairSuccessfully() throws Exception {
        KeyPair keyPair = handler.generateKeyPair();
        
        assertNotNull("KeyPair should not be null", keyPair);
        assertNotNull("Public key should not be null", keyPair.getPublic());
        assertNotNull("Private key should not be null", keyPair.getPrivate());
        assertEquals("Algorithm should be EdDSA", "EdDSA", keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void shouldGetKeyFactorySuccessfully() throws Exception {
        KeyFactory keyFactory = handler.getKeyFactory();
        
        assertNotNull("KeyFactory should not be null", keyFactory);
        assertEquals("Algorithm should be Ed25519", "Ed25519", keyFactory.getAlgorithm());
    }

    @Test
    public void shouldCreateJWKSuccessfully() throws Exception {
        KeyPair keyPair = handler.generateKeyPair();
        JWK jwk = handler.createJWK(keyPair);
        
        assertNotNull("JWK should not be null", jwk);
        assertTrue("JWK should be OctetKeyPair", jwk instanceof OctetKeyPair);
        assertEquals("Algorithm should be Ed25519", JWSAlgorithm.Ed25519, jwk.getAlgorithm());
    }

    @Test
    public void shouldCreateSignerSuccessfully() throws Exception {
        KeyPair keyPair = handler.generateKeyPair();
        JWK jwk = handler.createJWK(keyPair);
        JWSSigner signer = handler.createSigner(jwk);
        
        assertNotNull("Signer should not be null", signer);
    }

    @Test(expected = ClassCastException.class)
    public void shouldThrowExceptionWhenJWKIsInvalid() throws Exception {
        KeyPair rsaKeyPair = new RS256AlgorithmHandler().generateKeyPair();
        JWK invalidJwk = new RS256AlgorithmHandler().createJWK(rsaKeyPair);
        
        handler.createSigner(invalidJwk);
    }

    @Test
    public void shouldSignAndProduce64ByteSignature() throws Exception {
        KeyPair keyPair = handler.generateKeyPair();
        JWK jwk = handler.createJWK(keyPair);
        JWSSigner signer = handler.createSigner(jwk);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.Ed25519).build();
        byte[] payload = "test-payload".getBytes(StandardCharsets.UTF_8);

        com.nimbusds.jose.util.Base64URL signature = signer.sign(header, payload);
        assertNotNull("Signature must not be null", signature);
        byte[] sigBytes = signature.decode();
        assertEquals("Ed25519 signature should be 64 bytes", 64, sigBytes.length);

        assertTrue("supported algorithms must contain Ed25519", signer.supportedJWSAlgorithms().contains(JWSAlgorithm.Ed25519));
        assertNotNull("JCAContext should not be null", signer.getJCAContext());
    }

    @Test(expected = JOSEException.class)
    public void shouldThrowJOSEExceptionWhenPrivateKeyIsInvalidDuringSign() throws Exception {
        byte[] fakeX = new byte[32];
        for (int i = 0; i < fakeX.length; i++) fakeX[i] = (byte) (i + 1);
        byte[] invalidD = new byte[1];

        OctetKeyPair invalidOkp = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(fakeX))
                .d(Base64URL.encode(invalidD))
                .algorithm(JWSAlgorithm.Ed25519)
                .keyUse(KeyUse.SIGNATURE)
                .build();

        JWSSigner signer = handler.createSigner(invalidOkp);

        signer.sign(new JWSHeader.Builder(JWSAlgorithm.Ed25519).build(), "payload".getBytes(StandardCharsets.UTF_8));
    }

    @Test(expected = ClassCastException.class)
    public void shouldThrowExceptionWhenCreateJWKWithNonEdKeyPair() throws Exception {
        KeyPair rsaKeyPair = new RS256AlgorithmHandler().generateKeyPair();
        handler.createJWK(rsaKeyPair);
    }

}

