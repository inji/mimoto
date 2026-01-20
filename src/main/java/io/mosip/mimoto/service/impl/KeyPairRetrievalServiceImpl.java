package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.KeyGenerationException;
import io.mosip.mimoto.model.ProofSigningKey;
import io.mosip.mimoto.repository.ProofSigningKeyRepository;
import io.mosip.mimoto.service.KeyPairRetrievalService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.SigningKeyUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Base64;
import java.util.Optional;

/**
 * Service implementation for managing key pairs from database
 */
@Slf4j
@Service
public class KeyPairRetrievalServiceImpl implements KeyPairRetrievalService {

    @Autowired
    private ProofSigningKeyRepository proofSigningKeyRepository;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Override
    public KeyPair getKeyPairFromDB(String walletId, String base64EncodedWalletKey, SigningAlgorithm signingAlgorithm) throws KeyGenerationException, DecryptionException {
        log.debug("Retrieving key pair for walletId: {} with algorithm: {}", walletId, signingAlgorithm);

        // Step 1: Retrieve proof signing key from database
        Optional<ProofSigningKey> proofSigningKey = proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, signingAlgorithm.name());

        if (proofSigningKey.isEmpty()) {
            log.error("No proof signing key found for walletId: {} with algorithm: {}", walletId, signingAlgorithm);
            throw new KeyGenerationException("KEY_NOT_FOUND", "No proof signing key found for walletId: " + walletId + " with algorithm: " + signingAlgorithm);
        }

        // Step 2: Decode wallet key
        byte[] decodedWalletKey;
        try {
            decodedWalletKey = Base64.getDecoder().decode(base64EncodedWalletKey);
        } catch (IllegalArgumentException e) {
            log.error("Invalid base64 encoded wallet key for walletId: {}", walletId, e);
            throw new DecryptionException("INVALID_WALLET_KEY", "Invalid base64 encoded wallet key", e);
        }

        SecretKey walletKey = EncryptionDecryptionUtil.bytesToSecretKey(decodedWalletKey);

        // Step 3: Decode public key
        byte[] publicKeyBytes;
        try {
            publicKeyBytes = Base64.getDecoder().decode(proofSigningKey.get().getPublicKey());
        } catch (IllegalArgumentException e) {
            log.error("Invalid base64 encoded public key for walletId: {}", walletId, e);
            throw new KeyGenerationException("INVALID_PUBLIC_KEY", "Invalid base64 encoded public key", e);
        }

        // Step 4: Decrypt private key
        byte[] privateKeyInBytes;
        try {
            privateKeyInBytes = encryptionDecryptionUtil.decryptWithAES(walletKey, proofSigningKey.get().getEncryptedSecretKey());
        } catch (Exception e) {
            log.error("Failed to decrypt private key for walletId: {} with algorithm: {}", walletId, signingAlgorithm, e);
            throw new DecryptionException("DECRYPTION_FAILED", "Failed to decrypt private key for walletId: " + walletId, e);
        }

        // Step 5: Generate KeyPair from stored keys
        KeyPair keyPair;
        try {
            keyPair = SigningKeyUtil.generateKeyPair(signingAlgorithm, publicKeyBytes, privateKeyInBytes);
        } catch (Exception e) {
            log.error("Failed to generate KeyPair for signing algorithm: {} for walletId: {}", signingAlgorithm, walletId, e);
            throw new KeyGenerationException("KEY_GENERATION_FAILED", "Failed to generate KeyPair for algorithm: " + signingAlgorithm, e);
        }

        log.debug("Successfully retrieved KeyPair for signing algorithm: {} from database", signingAlgorithm);

        return keyPair;

    }
}
