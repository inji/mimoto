package io.mosip.mimoto.util.factory;

import io.mosip.mimoto.constant.SigningAlgorithm;

import java.util.EnumMap;
import java.util.Map;

/**
 * Factory for managing and retrieving algorithm-specific cryptographic handlers.
 * Uses the Strategy pattern to provide the appropriate handler implementation
 * for each signing algorithm.
 */
public class SigningAlgorithmHandlerFactory {

    private static final Map<SigningAlgorithm, SigningAlgorithmHandler> handlers;

    static {
        handlers = new EnumMap<>(SigningAlgorithm.class);
        handlers.put(SigningAlgorithm.RS256, new RS256AlgorithmHandler());
        handlers.put(SigningAlgorithm.ES256, new ES256AlgorithmHandler());
        handlers.put(SigningAlgorithm.ES256K, new ES256KAlgorithmHandler());
        handlers.put(SigningAlgorithm.ED25519, new Ed25519AlgorithmHandler());
    }

    /**
     * Gets the algorithm handler for the specified algorithm.
     * 
     * @param algorithm The signing algorithm
     * @return The corresponding algorithm handler
     * @throws IllegalArgumentException If the algorithm is not supported
     */
    public static SigningAlgorithmHandler getHandler(SigningAlgorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null");
        }
        SigningAlgorithmHandler handler = handlers.get(algorithm);
        if (handler == null) {
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
        return handler;
    }
}