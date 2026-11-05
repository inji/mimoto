package io.mosip.mimoto.service.device;

import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import io.mosip.mimoto.exception.DeviceAttestationException;
import io.mosip.mimoto.model.DevicePlatform;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static io.mosip.mimoto.exception.ErrorConstants.ATTESTATION_FAILED;

/**
 * Verifies Apple App Attest attestation objects, fully offline.
 * <p>
 * The wallet calls {@code DCAppAttestService.attestKey(keyId, clientDataHash)} with
 * {@code clientDataHash = SHA-256(UTF-8(challenge))}, where the challenge is the integrity nonce
 * {@code base64url(SHA-256(nonce + JWK thumbprint))} that {@link DeviceRegistrationService} passes as
 * {@code expectedNonce}. It sends the attestation object base64-encoded as the registration's integrity token.
 * <p>
 * Implements the steps in
 * <a href="https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server">
 * Validating apps that connect to your server</a>. The key identifier is derived from the attested key
 * (keyId = SHA-256 of its X9.62 public key) and checked against the authenticator data's credentialId.
 */
@Slf4j
@Component
public class AppleAppAttestVerifier implements DeviceAttestationVerifier {

    static final String BUNDLED_ROOT_CA = "device-attestation/Apple_App_Attestation_Root_CA.pem";
    /** credCert extension holding SHA-256(authData || clientDataHash). */
    static final String NONCE_EXTENSION_OID = "1.2.840.113635.100.8.2";
    static final String FORMAT = "apple-appattest";
    static final byte[] AAGUID_PRODUCTION = aaguid("appattest\0\0\0\0\0\0\0");
    /** Apple's docs name the development/sandbox value both ways; both are 16 bytes. */
    static final List<byte[]> AAGUID_DEVELOPMENT = List.of(aaguid("appattestdevelop"), aaguid("appattestsandbox"));
    static final String VALIDATION_CATEGORY_KEY = "apple_validation_category_01";
    static final String BUNDLE_VERSION_KEY = "apple_bundle_version_01";

    private static final int FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;
    private static final int FLAG_EXTENSION_DATA = 0x80;
    /** Generous bound: real attestation objects are about 5 KB. */
    private static final int MAX_ATTESTATION_BYTES = 64 * 1024;

    private final DeviceAttestationProperties.Ios config;
    private final TrustAnchor rootCa;
    private final Clock clock;

    @Autowired
    public AppleAppAttestVerifier(DeviceAttestationProperties properties) {
        this(properties, Clock.systemUTC());
    }

    AppleAppAttestVerifier(DeviceAttestationProperties properties, Clock clock) {
        this.config = properties.getIos();
        this.rootCa = new TrustAnchor(loadRootCa(config.getRootCaPath()), null);
        this.clock = clock;
    }

    @Override
    public DevicePlatform platform() {
        return DevicePlatform.IOS;
    }

    @Override
    public Map<String, Object> verify(String attestation, String expectedNonce) {
        if (StringUtils.isBlank(config.getTeamId()) || StringUtils.isBlank(config.getBundleId())) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, "App Attest team ID or bundle ID is not configured");
        }
        if (StringUtils.isBlank(attestation)) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, "Attestation is missing");
        }
        if (expectedNonce == null) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, "Expected nonce is missing");
        }

        // Decode the CBOR attestation object: { fmt, attStmt: { x5c, receipt }, authData }
        Map<?, ?> object = asMap(decodeCbor(decodeBase64(attestation)), "attestation object");
        check(FORMAT.equals(object.get("fmt")), "attestation format is not " + FORMAT);
        Map<?, ?> statement = asMap(object.get("attStmt"), "attStmt");
        byte[] authData = asBytes(object.get("authData"), "authData");
        byte[] receipt = asBytes(statement.get("receipt"), "receipt");
        List<X509Certificate> chain = certificates(statement.get("x5c"));

        // 1. x5c holds the credential certificate followed by the intermediate; validate up to Apple's root CA
        validateChain(chain);
        X509Certificate credCert = chain.get(0);

        // 2-3. nonce = SHA-256(authData || SHA-256(challenge))
        byte[] clientDataHash = sha256(expectedNonce.getBytes(StandardCharsets.UTF_8));
        byte[] nonce = sha256(concat(authData, clientDataHash));

        // 4. The credCert extension 1.2.840.113635.100.8.2 must contain that nonce
        check(MessageDigest.isEqual(nonce, nonceFromCertificate(credCert)), "nonce mismatch");

        // 5. keyId is SHA-256 of the credential public key in X9.62 uncompressed form
        byte[] keyId = sha256(uncompressedPoint(credCert));

        AuthenticatorData auth = AuthenticatorData.parse(authData);
        // 6. RP ID hash is SHA-256 of the App ID (team ID + "." + bundle ID)
        byte[] appIdHash = sha256((config.getTeamId() + "." + config.getBundleId()).getBytes(StandardCharsets.UTF_8));
        check(MessageDigest.isEqual(appIdHash, auth.rpIdHash()), "RP ID does not match the configured App ID");
        // 7. A fresh key has never signed an assertion
        check(auth.counter() == 0, "counter is not 0");
        // 8. aaguid tells development keys from production keys
        check(aaguidAllowed(auth.aaguid()), "aaguid does not match the " + config.getEnvironment() + " environment");
        // 9. credentialId is the key identifier
        check(MessageDigest.isEqual(keyId, auth.credentialId()), "credentialId does not match the attested key");
        // 10-11. Launch validation category and bundle version, carried by attestations from newer iOS releases
        Long validationCategory = checkExtensions(auth.extensions());

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("keyId", Base64.getEncoder().encodeToString(keyId));
        summary.put("environment", config.getEnvironment().name());
        summary.put("validationCategory", validationCategory);
        summary.put("bundleVersion", auth.extensions() == null ? null : auth.extensions().get(BUNDLE_VERSION_KEY));
        // Kept to request Apple's fraud risk metric later (number of attested keys on the device)
        summary.put("receipt", Base64.getEncoder().encodeToString(receipt));
        return summary;
    }

    private void validateChain(List<X509Certificate> chain) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            CertPath path = factory.generateCertPath(chain);
            PKIXParameters parameters = new PKIXParameters(Set.of(rootCa));
            // Apple publishes no CRL or OCSP endpoint for App Attest certificates
            parameters.setRevocationEnabled(false);
            parameters.setDate(Date.from(clock.instant()));
            CertPathValidator.getInstance("PKIX").validate(path, parameters);
        } catch (GeneralSecurityException e) {
            throw new DeviceAttestationException(ATTESTATION_FAILED,
                    "certificate chain does not lead to the Apple App Attestation Root CA: " + e.getMessage(), e);
        }
    }

    private Long checkExtensions(Map<?, ?> extensions) {
        if (extensions == null) {
            log.debug("App Attest authenticator data has no extensions; skipping validation category check");
            return null;
        }
        Object category = extensions.get(VALIDATION_CATEGORY_KEY);
        if (category != null) {
            check(category instanceof Long value && config.getAllowedValidationCategories().contains(value.intValue()),
                    "app validation category not accepted: " + category);
        }
        Object bundleVersion = extensions.get(BUNDLE_VERSION_KEY);
        check(bundleVersion == null || bundleVersion instanceof String, "bundle version is not a string");
        return (Long) category;
    }

    private boolean aaguidAllowed(byte[] aaguid) {
        if (config.getEnvironment() == DeviceAttestationProperties.Ios.Environment.PRODUCTION) {
            return Arrays.equals(AAGUID_PRODUCTION, aaguid);
        }
        return AAGUID_DEVELOPMENT.stream().anyMatch(expected -> Arrays.equals(expected, aaguid));
    }

    /**
     * Extracts the nonce from extension 1.2.840.113635.100.8.2, whose value is
     * {@code SEQUENCE { [1] EXPLICIT OCTET STRING nonce }}.
     */
    static byte[] nonceFromCertificate(X509Certificate certificate) {
        byte[] extension = certificate.getExtensionValue(NONCE_EXTENSION_OID);
        check(extension != null, "credential certificate has no nonce extension");
        try {
            Der extnValue = Der.parse(extension, 0, 0x04);           // OCTET STRING wrapping extnValue
            Der sequence = Der.parse(extnValue.content(), 0, 0x30);  // SEQUENCE
            Der tagged = Der.parse(sequence.content(), 0, 0xa1);     // [1] EXPLICIT
            Der nonce = Der.parse(tagged.content(), 0, 0x04);        // OCTET STRING
            return nonce.content();
        } catch (IllegalArgumentException e) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, "malformed nonce extension", e);
        }
    }

    static byte[] uncompressedPoint(X509Certificate certificate) {
        if (!(certificate.getPublicKey() instanceof ECPublicKey key) || key.getParams().getCurve().getField().getFieldSize() != 256) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, "credential certificate key is not EC P-256");
        }
        byte[] point = new byte[65];
        point[0] = 0x04;
        copyUnsigned(key.getW().getAffineX(), point, 1);
        copyUnsigned(key.getW().getAffineY(), point, 33);
        return point;
    }

    private static void copyUnsigned(BigInteger value, byte[] target, int offset) {
        byte[] bytes = value.toByteArray();
        int start = bytes.length > 32 ? bytes.length - 32 : 0;
        int length = bytes.length - start;
        System.arraycopy(bytes, start, target, offset + 32 - length, length);
    }

    private static List<X509Certificate> certificates(Object x5c) {
        check(x5c instanceof List<?> list && list.size() >= 2, "x5c must hold the credential and intermediate certificates");
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> chain = new ArrayList<>();
            for (Object der : (List<?>) x5c) {
                chain.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(asBytes(der, "x5c entry"))));
            }
            return chain;
        } catch (CertificateException e) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, "x5c holds an invalid certificate", e);
        }
    }

    static X509Certificate loadRootCa(String path) {
        try (InputStream in = StringUtils.isBlank(path)
                ? AppleAppAttestVerifier.class.getClassLoader().getResourceAsStream(BUNDLED_ROOT_CA)
                : Files.newInputStream(Path.of(path))) {
            if (in == null) {
                throw new IllegalStateException("Apple App Attestation Root CA not found on the classpath: " + BUNDLED_ROOT_CA);
            }
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (IOException | CertificateException e) {
            throw new IllegalStateException("Unable to load the Apple App Attestation Root CA", e);
        }
    }

    private static Object decodeCbor(byte[] bytes) {
        try {
            return CborReader.decodeSingle(bytes);
        } catch (IllegalArgumentException e) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, "attestation is not valid CBOR", e);
        }
    }

    private static byte[] decodeBase64(String value) {
        // Strict decoding: line breaks are tolerated, any other non-base64 character is rejected
        String compact = value.replaceAll("\\s", "");
        try {
            byte[] bytes = compact.indexOf('-') >= 0 || compact.indexOf('_') >= 0
                    ? Base64.getUrlDecoder().decode(compact)
                    : Base64.getDecoder().decode(compact);
            check(bytes.length > 0 && bytes.length <= MAX_ATTESTATION_BYTES, "attestation size is out of range");
            return bytes;
        } catch (IllegalArgumentException e) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, "attestation is not base64", e);
        }
    }

    private static Map<?, ?> asMap(Object value, String name) {
        check(value instanceof Map<?, ?>, name + " is not a CBOR map");
        return (Map<?, ?>) value;
    }

    private static byte[] asBytes(Object value, String name) {
        check(value instanceof byte[], name + " is missing or not a byte string");
        return (byte[]) value;
    }

    static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private static byte[] aaguid(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static void check(boolean condition, String failure) {
        if (!condition) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, failure);
        }
    }

    /**
     * WebAuthn authenticator data: rpIdHash(32) | flags(1) | counter(4) | aaguid(16) | credentialIdLength(2) |
     * credentialId | COSE public key (CBOR) | extensions (CBOR map, when flagged).
     */
    record AuthenticatorData(byte[] rpIdHash, long counter, byte[] aaguid, byte[] credentialId, Map<?, ?> extensions) {

        static AuthenticatorData parse(byte[] data) {
            check(data.length >= 37 + 16 + 2, "authData is too short");
            byte[] rpIdHash = Arrays.copyOfRange(data, 0, 32);
            int flags = data[32] & 0xff;
            long counter = ((data[33] & 0xffL) << 24) | ((data[34] & 0xffL) << 16) | ((data[35] & 0xffL) << 8) | (data[36] & 0xffL);
            check((flags & FLAG_ATTESTED_CREDENTIAL_DATA) != 0, "authData has no attested credential data");
            byte[] aaguid = Arrays.copyOfRange(data, 37, 53);
            int credentialIdLength = ((data[53] & 0xff) << 8) | (data[54] & 0xff);
            int credentialEnd = 55 + credentialIdLength;
            check(credentialIdLength == 32 && credentialEnd <= data.length, "authData credentialId has an unexpected length");
            byte[] credentialId = Arrays.copyOfRange(data, 55, credentialEnd);
            Map<?, ?> extensions = null;
            try {
                CborReader reader = new CborReader(data, credentialEnd);
                check(reader.read() instanceof Map<?, ?>, "authData public key is not a COSE key");
                if ((flags & FLAG_EXTENSION_DATA) != 0) {
                    extensions = asMap(reader.read(), "authData extensions");
                }
                check(reader.position() == data.length, "authData has trailing bytes");
            } catch (IllegalArgumentException e) {
                throw new DeviceAttestationException(ATTESTATION_FAILED, "authData is malformed", e);
            }
            return new AuthenticatorData(rpIdHash, counter, aaguid, credentialId, extensions);
        }
    }

    /** A single DER TLV with a short or long definite length. */
    record Der(int tag, byte[] content) {

        static Der parse(byte[] data, int offset, int expectedTag) {
            if (offset + 2 > data.length) {
                throw new IllegalArgumentException("DER element truncated");
            }
            int tag = data[offset] & 0xff;
            if (tag != expectedTag) {
                throw new IllegalArgumentException("Unexpected DER tag " + tag);
            }
            int length = data[offset + 1] & 0xff;
            int start = offset + 2;
            if (length > 0x80) {
                int lengthBytes = length & 0x7f;
                if (lengthBytes > 3 || start + lengthBytes > data.length) {
                    throw new IllegalArgumentException("Unsupported DER length");
                }
                length = 0;
                for (int i = 0; i < lengthBytes; i++) {
                    length = (length << 8) | (data[start + i] & 0xff);
                }
                start += lengthBytes;
            } else if (length == 0x80) {
                throw new IllegalArgumentException("Indefinite DER length");
            }
            if (start + length > data.length) {
                throw new IllegalArgumentException("DER element truncated");
            }
            return new Der(tag, Arrays.copyOfRange(data, start, start + length));
        }
    }
}
