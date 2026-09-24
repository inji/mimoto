package io.mosip.mimoto.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import io.mosip.mimoto.constant.BindingMethod;
import io.mosip.mimoto.constant.SigningAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

@Component
@Slf4j
public class BindingMethodUtil {

    // Multicodec varint prefixes from the did:key method registry
    private static final byte[] MULTICODEC_ED25519 = {(byte) 0xed, 0x01};
    private static final byte[] MULTICODEC_ES256K   = {(byte) 0xe7, 0x01};
    private static final byte[] MULTICODEC_ES256    = {(byte) 0x80, 0x24};
    private static final byte[] MULTICODEC_RS256    = {(byte) 0x85, 0x24};

    private static final String BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BindingMethod DEFAULT_BINDING_METHOD = BindingMethod.DID_JWK;

    @Value("${binding.methods.supported.order:jwk,did:jwk,did:key}")
    private String bindingMethodsPriorityOrder;

    public List<String> getBindingMethodsPriorityOrder() {
        return Arrays.stream(bindingMethodsPriorityOrder.split(","))
                .map(String::trim)
                .collect(Collectors.toList());
    }

    /**
     * Selects the binding method to use based on the issuer's advertised list and the
     * configured wallet priority order. Falls back to did:jwk if no match or list is empty.
     */
    public BindingMethod selectBindingMethod(List<String> issuerSupported) {
        if (issuerSupported == null || issuerSupported.isEmpty()) {
            log.warn("Issuer has no cryptographic_binding_methods_supported, falling back to {}", DEFAULT_BINDING_METHOD);
            return DEFAULT_BINDING_METHOD;
        }
        List<String> priorityList = getBindingMethodsPriorityOrder();
        log.info("Selecting binding method — issuer supports: {}, wallet priority: {}", issuerSupported, priorityList);
        BindingMethod selected = priorityList.stream()
                .filter(issuerSupported::contains)
                .findFirst()
                .map(method -> {
                    try {
                        return BindingMethod.fromString(method);
                    } catch (IllegalArgumentException e) {
                        return DEFAULT_BINDING_METHOD;
                    }
                })
                .orElseGet(() -> {
                    log.warn("No matching binding method found in issuer list: {}, falling back to {}", issuerSupported, DEFAULT_BINDING_METHOD);
                    return DEFAULT_BINDING_METHOD;
                });
        log.info("Selected binding method: {}", selected);
        return selected;
    }

    /**
     * Encodes a JWK as a did:jwk identifier: did:jwk:<base64url(json)>#0
     */
    public static String encodeDidJwk(JWK jwk) {
        String jwkJson = jwk.toPublicJWK().toString();
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(jwkJson.getBytes(StandardCharsets.UTF_8));
        return "did:jwk:" + encoded + "#0";
    }

    /**
     * Encodes a JWK as a did:key identifier with verification method fragment:
     * did:key:z<base58btc(multicodec||keyBytes)>#z<base58btc(multicodec||keyBytes)>
     */
    public static String encodeDidKey(JWK jwk, SigningAlgorithm algorithm) throws JOSEException {
        try {
            byte[] prefix = getMulticodecPrefix(algorithm);
            byte[] keyBytes = getRawPublicKeyBytes(jwk, algorithm);
            byte[] multicodec = new byte[prefix.length + keyBytes.length];
            System.arraycopy(prefix, 0, multicodec, 0, prefix.length);
            System.arraycopy(keyBytes, 0, multicodec, prefix.length, keyBytes.length);
            String encoded = "z" + encodeBase58(multicodec);
            return "did:key:" + encoded + "#" + encoded;
        } catch (IOException e) {
            throw new JOSEException("Failed to encode did:key for algorithm " + algorithm + ": " + e.getMessage(), e);
        }
    }

    private static byte[] getMulticodecPrefix(SigningAlgorithm algorithm) {
        return switch (algorithm) {
            case ED25519 -> MULTICODEC_ED25519;
            case ES256K  -> MULTICODEC_ES256K;
            case ES256   -> MULTICODEC_ES256;
            case RS256   -> MULTICODEC_RS256;
        };
    }

    private static byte[] getRawPublicKeyBytes(JWK jwk, SigningAlgorithm algorithm) throws IOException {
        return switch (algorithm) {
            case ED25519       -> ((OctetKeyPair) jwk).getX().decode();
            case ES256, ES256K -> compressedEcPoint((ECKey) jwk);
            case RS256         -> pkcs1PublicKeyDer((RSAKey) jwk);
        };
    }

    // SEC1 compressed point: parity byte (0x02 even y / 0x03 odd y) + 32-byte x coordinate
    private static byte[] compressedEcPoint(ECKey ecKey) {
        byte[] x = toFixedLength(ecKey.getX().decode(), 32);
        byte[] y = toFixedLength(ecKey.getY().decode(), 32);
        byte parity = (y[y.length - 1] & 1) == 0 ? (byte) 0x02 : (byte) 0x03;
        byte[] compressed = new byte[33];
        compressed[0] = parity;
        System.arraycopy(x, 0, compressed, 1, 32);
        return compressed;
    }

    // PKCS#1 DER-encoded RSAPublicKey via BouncyCastle (bcprov-jdk18on already a dependency)
    private static byte[] pkcs1PublicKeyDer(RSAKey rsaKey) throws IOException {
        BigInteger n = new BigInteger(1, rsaKey.getModulus().decode());
        BigInteger e = new BigInteger(1, rsaKey.getPublicExponent().decode());
        return new RSAPublicKey(n, e).getEncoded();
    }

    // Ensures byte array is exactly `length` bytes — pads with leading zeros if short, strips if long
    private static byte[] toFixedLength(byte[] bytes, int length) {
        if (bytes.length == length) return bytes;
        byte[] result = new byte[length];
        if (bytes.length < length) {
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
        } else {
            System.arraycopy(bytes, bytes.length - length, result, 0, length);
        }
        return result;
    }

    // Base58btc encoding using the Bitcoin/IPFS alphabet — no external dependency needed
    private static String encodeBase58(byte[] input) {
        int leadingZeros = 0;
        for (byte b : input) {
            if (b == 0) leadingZeros++;
            else break;
        }
        BigInteger bigInt = new BigInteger(1, input);
        BigInteger base = BigInteger.valueOf(58);
        StringBuilder sb = new StringBuilder();
        while (bigInt.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] divRem = bigInt.divideAndRemainder(base);
            bigInt = divRem[0];
            sb.insert(0, BASE58_ALPHABET.charAt(divRem[1].intValue()));
        }
        for (int i = 0; i < leadingZeros; i++) {
            sb.insert(0, '1');
        }
        return sb.toString();
    }
}