package io.mosip.mimoto.util.factory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import io.mosip.mimoto.constant.SigningAlgorithmConstants;

import java.security.*;
import java.security.interfaces.*;

/**
 * Algorithm handler for RS256 (RSA with SHA-256) signing.
 * Uses RSA 2048-bit keys and BouncyCastle provider for signing operations.
 */
public class RS256AlgorithmHandler implements SigningAlgorithmHandler {

    private static final int RSA_KEY_SIZE = 2048;

    @Override
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(SigningAlgorithmConstants.RSA);
        generator.initialize(RSA_KEY_SIZE);
        return generator.generateKeyPair();
    }

    @Override
    public KeyFactory getKeyFactory() throws NoSuchAlgorithmException {
        return KeyFactory.getInstance(SigningAlgorithmConstants.RSA);
    }

    @Override
    public JWK createJWK(KeyPair keyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        return new RSAKey.Builder(publicKey).privateKey(privateKey).algorithm(JWSAlgorithm.RS256).keyUse(KeyUse.SIGNATURE).build();
    }

    @Override
    public JWSSigner createSigner(JWK jwk) throws JOSEException {
        RSASSASigner signer = new RSASSASigner((RSAKey) jwk);
        signer.getJCAContext().setProvider(BouncyCastleProviderUtil.getProvider());
        return signer;
    }

}