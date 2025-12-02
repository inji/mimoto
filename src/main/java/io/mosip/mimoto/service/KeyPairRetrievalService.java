package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.KeyGenerationException;

import java.security.KeyPair;

/**
 * Service interface for managing key pairs from database
 */
public interface KeyPairRetrievalService {

    /**
     * Retrieves a key pair from the database for the given wallet ID and signing algorithm
     *
     * @param walletId The wallet ID
     * @param base64EncodedWalletKey The base64 encoded wallet key for decryption
     * @param signingAlgorithm The signing algorithm
     * @return The key pair
     * @throws KeyGenerationException if key generation or retrieval fails
     * @throws DecryptionException if decryption of private key fails
     */
    KeyPair getKeyPairFromDB(String walletId, String base64EncodedWalletKey, SigningAlgorithm signingAlgorithm) throws KeyGenerationException, DecryptionException;
}
