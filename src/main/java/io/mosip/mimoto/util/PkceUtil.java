package io.mosip.mimoto.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * RFC 7636 PKCE helpers. The verifier never leaves Mimoto.
 */
public final class PkceUtil {

    static final String UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    private static final int VALUE_LENGTH = 43;
    private static final SecureRandom RANDOM = new SecureRandom();

    private PkceUtil() {
    }

    public static String generateValue() {
        char[] chars = new char[VALUE_LENGTH];
        for (int i = 0; i < VALUE_LENGTH; i++) {
            chars[i] = UNRESERVED.charAt(RANDOM.nextInt(UNRESERVED.length()));
        }
        return new String(chars);
    }

    public static String s256Challenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to create PKCE code_challenge", e);
        }
    }
}
