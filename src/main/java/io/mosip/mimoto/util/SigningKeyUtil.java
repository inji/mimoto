package io.mosip.mimoto.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.*;
import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.exception.KeyGenerationException;
import io.mosip.mimoto.util.factory.SigningAlgorithmHandler;
import io.mosip.mimoto.util.factory.SigningAlgorithmHandlerFactory;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import io.mosip.mimoto.model.KeyMetadata;
import io.mosip.mimoto.model.ProofSigningKey;

import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import static io.mosip.mimoto.exception.ErrorConstants.ENCRYPTION_FAILED;

/**
 * Unified utility for key generation and JWT signing operations.
 */
@Slf4j
public class SigningKeyUtil {

    private static final int JWT_EXPIRATION_SECONDS = 18000; // 5 hours
    private static final String OPENID4VCI_PROOF_JWT = "openid4vci-proof+jwt";
    
    /**
     * Generates a key pair for the given signing algorithm.
     *
     * @param algorithm The algorithm to use (e.g., "RS256", "ES256", "ES256K", "Ed25519").
     * @return KeyPair object.
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateKeyPair(SigningAlgorithm algorithm) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        SigningAlgorithmHandler handler = SigningAlgorithmHandlerFactory.getHandler(algorithm);
        return handler.generateKeyPair();
    }

    /**
     * Reconstructs a KeyPair from stored byte arrays (from database).
     *
     * @param algorithm       The signing algorithm
     * @param publicKeyBytes  Public key bytes
     * @param privateKeyBytes Private key bytes
     * @return Reconstructed KeyPair
     * @throws NoSuchAlgorithmException If the algorithm is not supported
     * @throws InvalidAlgorithmParameterException If algorithm parameters are invalid
     * @throws NoSuchProviderException If the provider is not available
     * @throws InvalidKeySpecException If the key bytes are invalid
     */
    public static KeyPair generateKeyPair(SigningAlgorithm algorithm, byte[] publicKeyBytes, byte[] privateKeyBytes) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeySpecException {

        SigningAlgorithmHandler handler = SigningAlgorithmHandlerFactory.getHandler(algorithm);
        KeyFactory keyFactory = handler.getKeyFactory();

        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Generates a secret key for encryption (e.g., AES).
     * This is separate from signing keys and remains algorithm-agnostic.
     *
     * @param algorithm The algorithm to use (e.g., "AES").
     * @param keySize   The key size in bits.
     * @return SecretKey object.
     */
    public static SecretKey generateEncryptionKey(String algorithm, int keySize) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
            keyGenerator.init(keySize);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenerationException(ENCRYPTION_FAILED.getErrorCode(), ENCRYPTION_FAILED.getErrorMessage(), e);
        }
    }

    /**
     * Generates a complete signed JWT token.
     *
     * @param signingAlgorithm The signing algorithm to use
     * @param audience         The JWT audience
     * @param clientId         The client ID (used as subject and issuer)
     * @param cNonce           The challenge nonce
     * @param keyPair          The key pair to use for signing
     * @return Serialized signed JWT string
     * @throws JOSEException If JWT generation fails
     */
    public static String generateJwt(SigningAlgorithm signingAlgorithm, String audience, String clientId, String cNonce, KeyPair keyPair) throws JOSEException {
        SigningAlgorithmHandler handler = SigningAlgorithmHandlerFactory.getHandler(signingAlgorithm);

        // Use handler to create JWK and signer
        JWK jwk = handler.createJWK(keyPair);
        JWSSigner signer = handler.createSigner(jwk);

        JWTClaimsSet claimsSet = createClaims(clientId, audience, cNonce);
        JWSHeader header = new JWSHeader.Builder(signingAlgorithm.getJWSAlgorithm()).type(new JOSEObjectType(OPENID4VCI_PROOF_JWT)).jwk(jwk.toPublicJWK()).build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    /**
     * Creates a JWK (JSON Web Key) from a KeyPair.
     *
     * @param algorithm The signing algorithm
     * @param keyPair   The key pair
     * @return JWK object
     */
    public static JWK generateJwk(SigningAlgorithm algorithm, KeyPair keyPair) {
        SigningAlgorithmHandler handler = SigningAlgorithmHandlerFactory.getHandler(algorithm);
        return handler.createJWK(keyPair);
    }

    /**
     * Creates a JWSSigner from a JWK.
     *
     * @param algorithm The signing algorithm
     * @param jwk       The JSON Web Key
     * @return JWSSigner object
     * @throws JOSEException If signer creation fails
     */
    public static JWSSigner createSigner(SigningAlgorithm algorithm, JWK jwk) throws JOSEException {
        SigningAlgorithmHandler handler = SigningAlgorithmHandlerFactory.getHandler(algorithm);
        return handler.createSigner(jwk);
    }

    /**
     * Creates a ProofSigningKey entity for the given algorithm.
     * Generates a key pair and wraps it with metadata for database storage.
     *
     * @param algorithm The signing algorithm to use
     * @return ProofSigningKey object ready for database persistence
     * @throws KeyGenerationException If key generation fails
     */
    public static ProofSigningKey createProofSigningKey(SigningAlgorithm algorithm) {
        try {
            KeyPair keyPair = generateKeyPair(algorithm);

            KeyMetadata keyMetadata = new KeyMetadata();
            keyMetadata.setAlgorithmName(algorithm.name());

            ProofSigningKey proofSigningKey = new ProofSigningKey();
            proofSigningKey.setId(UUID.randomUUID().toString());
            proofSigningKey.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            proofSigningKey.setSecretKey(keyPair.getPrivate());
            proofSigningKey.setKeyMetadata(keyMetadata);
            proofSigningKey.setCreatedAt(Instant.now());
            proofSigningKey.setUpdatedAt(Instant.now());

            return proofSigningKey;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            log.error("Error while generating key", e);
            throw new KeyGenerationException(ENCRYPTION_FAILED.getErrorCode(), "Failed to generate proof signing key for algorithm: " + algorithm, e);
        }
    }

    /**
     * Creates JWT claims set with standard fields.
     */
    private static JWTClaimsSet createClaims(String clientId, String audience, String cNonce) {
        long nowSeconds = System.currentTimeMillis() / 1000;
        Date issuedAt = new Date(nowSeconds * 1000);
        Date expiresAt = new Date((nowSeconds + JWT_EXPIRATION_SECONDS) * 1000);

        return new JWTClaimsSet.Builder().subject(clientId).audience(audience).issuer(clientId).issueTime(issuedAt).expirationTime(expiresAt).claim("nonce", cNonce).build();
    }
}