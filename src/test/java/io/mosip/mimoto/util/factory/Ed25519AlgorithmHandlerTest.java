package io.mosip.mimoto.util.factory;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import org.junit.Test;

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
}

