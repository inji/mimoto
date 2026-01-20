package io.mosip.mimoto.util;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.exception.KeyGenerationException;
import io.mosip.mimoto.model.ProofSigningKey;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.*;

/**
 * Test cases for SigningKeyUtil.
 */
public class SigningKeyUtilTest {

    @Before
    public void setUp() {
        // Ensure BouncyCastle provider is registered
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    @Test
    public void shouldGenerateKeyPairForRS256() throws Exception {
        KeyPair keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.RS256);
        
        assertNotNull("KeyPair should not be null", keyPair);
        assertEquals("Algorithm should be RSA", "RSA", keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void shouldGenerateKeyPairForES256() throws Exception {
        KeyPair keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.ES256);
        
        assertNotNull("KeyPair should not be null", keyPair);
        assertEquals("Algorithm should be EC", "EC", keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void shouldGenerateKeyPairForES256K() throws Exception {
        KeyPair keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.ES256K);
        
        assertNotNull("KeyPair should not be null", keyPair);
        assertEquals("Algorithm should be EC", "EC", keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void shouldGenerateKeyPairForED25519() throws Exception {
        KeyPair keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.ED25519);
        
        assertNotNull("KeyPair should not be null", keyPair);
        assertEquals("Algorithm should be EdDSA", "EdDSA", keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void shouldGenerateKeyPair() throws Exception {
        KeyPair originalKeyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.RS256);
        byte[] publicKeyBytes = originalKeyPair.getPublic().getEncoded();
        byte[] privateKeyBytes = originalKeyPair.getPrivate().getEncoded();
        
        KeyPair reconstructedKeyPair = SigningKeyUtil.generateKeyPair(
                SigningAlgorithm.RS256, publicKeyBytes, privateKeyBytes);
        
        assertNotNull("Reconstructed KeyPair should not be null", reconstructedKeyPair);
        assertEquals("Public key algorithm should match", 
                     originalKeyPair.getPublic().getAlgorithm(), 
                     reconstructedKeyPair.getPublic().getAlgorithm());
    }

    @Test(expected = InvalidKeySpecException.class)
    public void shouldThrowExceptionForInvalidKeyBytes() throws Exception {
        byte[] invalidPublicKey = new byte[]{1, 2, 3};
        byte[] invalidPrivateKey = new byte[]{4, 5, 6};
        
        SigningKeyUtil.generateKeyPair(
                SigningAlgorithm.RS256, invalidPublicKey, invalidPrivateKey);
    }

    @Test
    public void shouldGenerateEncryptionKey() {
        SecretKey secretKey = SigningKeyUtil.generateEncryptionKey("AES", 256);
        
        assertNotNull("SecretKey should not be null", secretKey);
        assertEquals("Algorithm should be AES", "AES", secretKey.getAlgorithm());
    }

    @Test(expected = KeyGenerationException.class)
    public void shouldThrowExceptionForUnsupportedEncryptionAlgorithm() {
        SigningKeyUtil.generateEncryptionKey("UNSUPPORTED", 256);
    }

    @Test
    public void shouldGenerateJwtSuccessfully() throws Exception {
        KeyPair keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.RS256);
        String jwt = SigningKeyUtil.generateJwt(
                SigningAlgorithm.RS256,
                "test-audience",
                "test-client-id",
                "test-nonce",
                keyPair
        );
        
        assertNotNull("JWT should not be null", jwt);
        assertFalse("JWT should not be empty", jwt.isEmpty());
        
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        assertEquals("Subject should match", "test-client-id", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("Audience should match", "test-audience", signedJWT.getJWTClaimsSet().getAudience().getFirst());
        assertEquals("Nonce should match", "test-nonce", signedJWT.getJWTClaimsSet().getStringClaim("nonce"));
    }

    @Test
    public void shouldGenerateJwkSuccessfully() throws Exception {
        KeyPair keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.RS256);
        JWK jwk = SigningKeyUtil.generateJwk(SigningAlgorithm.RS256, keyPair);
        
        assertNotNull("JWK should not be null", jwk);
        assertNotNull("JWK algorithm should not be null", jwk.getAlgorithm());
    }

    @Test
    public void shouldCreateSignerSuccessfully() throws Exception {
        KeyPair keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.RS256);
        JWK jwk = SigningKeyUtil.generateJwk(SigningAlgorithm.RS256, keyPair);
        JWSSigner signer = SigningKeyUtil.createSigner(SigningAlgorithm.RS256, jwk);
        
        assertNotNull("Signer should not be null", signer);
    }

    @Test(expected = ClassCastException.class)
    public void shouldThrowExceptionForInvalidJwkInSignerCreation() throws Exception {
        KeyPair rsaKeyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.RS256);
        JWK rsaJwk = SigningKeyUtil.generateJwk(SigningAlgorithm.RS256, rsaKeyPair);
        
        // Try to use RS256 JWK with ES256 signer
        SigningKeyUtil.createSigner(SigningAlgorithm.ES256, rsaJwk);
    }

    @Test
    public void shouldCreateProofSigningKeySuccessfully() {
        ProofSigningKey proofSigningKey = SigningKeyUtil.createProofSigningKey(SigningAlgorithm.RS256);
        
        assertNotNull("ProofSigningKey should not be null", proofSigningKey);
        assertNotNull("ID should not be null", proofSigningKey.getId());
        assertNotNull("Public key should not be null", proofSigningKey.getPublicKey());
        assertNotNull("Secret key should not be null", proofSigningKey.getSecretKey());
        assertNotNull("Key metadata should not be null", proofSigningKey.getKeyMetadata());
        assertEquals("Algorithm name should match", 
                     SigningAlgorithm.RS256.name(), 
                     proofSigningKey.getKeyMetadata().getAlgorithmName());
    }

    @Test
    public void shouldCreateProofSigningKeyForAllAlgorithms() {
        for (SigningAlgorithm algorithm : SigningAlgorithm.values()) {
            ProofSigningKey proofSigningKey = SigningKeyUtil.createProofSigningKey(algorithm);
            
            assertNotNull("ProofSigningKey should not be null for " + algorithm, proofSigningKey);
            assertEquals("Algorithm name should match for " + algorithm,
                         algorithm.name(),
                         proofSigningKey.getKeyMetadata().getAlgorithmName());
        }
    }
}

