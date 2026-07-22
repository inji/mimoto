package io.mosip.mimoto.constant;

import com.nimbusds.jose.JWSAlgorithm;

public enum SigningAlgorithm {
    RS256(JWSAlgorithm.RS256, "RSA"),
    ES256(JWSAlgorithm.ES256, "EC"),
    ES256K(JWSAlgorithm.ES256K, "EC"),
    ED25519(JWSAlgorithm.Ed25519, "Ed25519");

    private final JWSAlgorithm jwsAlgorithm;
    private final String keyFactoryAlgorithm;

    SigningAlgorithm(JWSAlgorithm jwsAlgorithm, String keyFactoryAlgorithm) {
        this.jwsAlgorithm = jwsAlgorithm;
        this.keyFactoryAlgorithm = keyFactoryAlgorithm;
    }

    public JWSAlgorithm getJWSAlgorithm() {
        return jwsAlgorithm;
    }

    public String getKeyFactoryAlgorithm() {
        return keyFactoryAlgorithm;
    }

    public static SigningAlgorithm fromString(String value) {
        return switch (value.toUpperCase()) {
            case "RS256" -> RS256;
            case "ES256" -> ES256;
            case "ES256K" -> ES256K;
            case "ED25519", "EdDSA" -> ED25519;
            default -> throw new IllegalArgumentException("Unsupported signing algorithm: " + value);
        };
    }

}
