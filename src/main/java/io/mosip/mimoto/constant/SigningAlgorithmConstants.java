package io.mosip.mimoto.constant;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class SigningAlgorithmConstants {

    // Algorithm Names
    public static final String RSA = "RSA";
    public static final String EC = "EC";
    public static final String ED25519 = "Ed25519";

    // EC curve names (JCA)
    public static final String CURVE_SECP256K1 = "secp256k1";
    public static final String CURVE_SECP256R1 = "secp256r1";

    // Provider Names
    public static final String BC_PROVIDER = "BC";
}
