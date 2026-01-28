package io.mosip.mimoto.util.factory;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;

/**
 * Strategy interface for algorithm-specific cryptographic operations.
 * Implementations encapsulate the logic for key generation, key factory retrieval,
 * JWK creation, and JWSSigner creation for a specific signing algorithm.
 * 
 * @implNote All implementations should be thread-safe and stateless.
 */
public interface SigningAlgorithmHandler {

    KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException;

    KeyFactory getKeyFactory() throws NoSuchAlgorithmException, NoSuchProviderException;

    JWK createJWK(KeyPair keyPair);

    JWSSigner createSigner(JWK jwk) throws JOSEException;

}
