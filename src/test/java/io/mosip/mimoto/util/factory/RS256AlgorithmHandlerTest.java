package io.mosip.mimoto.util.factory;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;

import static org.junit.Assert.*;

/**
 * Test cases for RS256AlgorithmHandler.
 */
public class RS256AlgorithmHandlerTest {

    private final RS256AlgorithmHandler handler = new RS256AlgorithmHandler();

    @Before
    public void setUp() {
        // Ensure BouncyCastle provider is registered (required for signing operations)
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void shouldGenerateKeyPairSuccessfully() throws Exception {
        KeyPair keyPair = handler.generateKeyPair();
        
        assertNotNull("KeyPair should not be null", keyPair);
        assertNotNull("Public key should not be null", keyPair.getPublic());
        assertNotNull("Private key should not be null", keyPair.getPrivate());
        assertEquals("Algorithm should be RSA", "RSA", keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void shouldGetKeyFactorySuccessfully() throws Exception {
        KeyFactory keyFactory = handler.getKeyFactory();
        
        assertNotNull("KeyFactory should not be null", keyFactory);
        assertEquals("Algorithm should be RSA", "RSA", keyFactory.getAlgorithm());
    }

    @Test
    public void shouldCreateJWKSuccessfully() throws Exception {
        KeyPair keyPair = handler.generateKeyPair();
        JWK jwk = handler.createJWK(keyPair);
        
        assertNotNull("JWK should not be null", jwk);
        assertTrue("JWK should be RSAKey", jwk instanceof RSAKey);
        assertEquals("Algorithm should be RS256", JWSAlgorithm.RS256, jwk.getAlgorithm());
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
        // Create invalid JWK (not RSAKey)
        KeyPair ecKeyPair = new ES256AlgorithmHandler().generateKeyPair();
        JWK invalidJwk = new ES256AlgorithmHandler().createJWK(ecKeyPair);
        
        handler.createSigner(invalidJwk);
    }
}

