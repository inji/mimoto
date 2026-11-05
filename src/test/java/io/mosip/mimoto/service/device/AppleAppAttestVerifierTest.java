package io.mosip.mimoto.service.device;

import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import io.mosip.mimoto.config.device.DeviceAttestationProperties.Ios.Environment;
import io.mosip.mimoto.exception.DeviceAttestationException;
import io.mosip.mimoto.model.DevicePlatform;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Uses a real App Attest attestation (iOS 14.4, development environment) published with the Apache-2.0
 * licensed github.com/veehaitch/devicecheck-appattest test resources. Its credential certificate is valid
 * from 2021-01-22T12:13:35Z to 2021-01-25T12:13:35Z, so verification runs on a fixed clock inside that window.
 */
public class AppleAppAttestVerifierTest {

    private static final String TEAM_ID = "6MURL8TA57";
    private static final String BUNDLE_ID = "de.vincent-haupert.apple-appattest-poc";
    /** The challenge the sample was attested with: clientDataHash = SHA-256("wurzelpfropf"). */
    private static final String CHALLENGE = "wurzelpfropf";
    private static final String KEY_ID = "YmbJO4x5nEHUvncp9zdWuVZjNBEMgJn3cdSToAXQe3M=";
    private static final Instant ATTESTED_AT = Instant.parse("2021-01-23T12:13:33.335Z");

    private DeviceAttestationProperties properties;
    private String attestation;

    @Before
    public void setUp() throws IOException {
        properties = new DeviceAttestationProperties();
        properties.getIos().setTeamId(TEAM_ID);
        properties.getIos().setBundleId(BUNDLE_ID);
        properties.getIos().setEnvironment(Environment.DEVELOPMENT);
        try (InputStream in = getClass().getClassLoader()
                .getResourceAsStream("device-attestation/app-attest-sample-ios-14.4.b64")) {
            assertNotNull(in, "sample attestation resource is missing");
            attestation = new String(in.readAllBytes(), StandardCharsets.US_ASCII).trim();
        }
    }

    private AppleAppAttestVerifier verifier(Instant now) {
        return new AppleAppAttestVerifier(properties, Clock.fixed(now, ZoneOffset.UTC));
    }

    private Map<String, Object> verify(String attestation, String challenge) {
        return verifier(ATTESTED_AT).verify(attestation, challenge);
    }

    private static void assertRejected(String expectedMessagePart, Runnable call) {
        DeviceAttestationException e = assertThrows(DeviceAttestationException.class, call::run);
        assertTrue(e.getMessage().contains(expectedMessagePart),
                () -> "expected '" + expectedMessagePart + "' in: " + e.getMessage());
    }

    @Test
    public void platformIsIos() {
        assertEquals(DevicePlatform.IOS, verifier(ATTESTED_AT).platform());
    }

    @Test
    public void acceptsGenuineAttestation() {
        Map<String, Object> summary = verify(attestation, CHALLENGE);

        assertEquals(KEY_ID, summary.get("keyId"));
        assertEquals("DEVELOPMENT", summary.get("environment"));
        assertNotNull(summary.get("receipt"));
        // iOS 14.4 attestations carry no authenticator data extensions
        assertNull(summary.get("validationCategory"));
    }

    @Test
    public void acceptsUrlSafeBase64() {
        String urlSafe = Base64.getUrlEncoder().withoutPadding().encodeToString(Base64.getDecoder().decode(attestation));
        assertEquals(KEY_ID, verify(urlSafe, CHALLENGE).get("keyId"));
    }

    @Test
    public void acceptsLineWrappedBase64() {
        String wrapped = Base64.getMimeEncoder().encodeToString(Base64.getDecoder().decode(attestation));
        assertEquals(KEY_ID, verify(wrapped, CHALLENGE).get("keyId"));
    }

    @Test
    public void rejectsOtherChallenge() {
        assertRejected("nonce mismatch", () -> verify(attestation, CHALLENGE + "x"));
    }

    @Test
    public void rejectsOtherBundleId() {
        properties.getIos().setBundleId("io.mosip.inji.wallet");
        assertRejected("RP ID", () -> verify(attestation, CHALLENGE));
    }

    @Test
    public void rejectsOtherTeamId() {
        properties.getIos().setTeamId("ABCDE12345");
        assertRejected("RP ID", () -> verify(attestation, CHALLENGE));
    }

    @Test
    public void rejectsDevelopmentKeyInProduction() {
        properties.getIos().setEnvironment(Environment.PRODUCTION);
        assertRejected("aaguid", () -> verify(attestation, CHALLENGE));
    }

    @Test
    public void rejectsExpiredCredentialCertificate() {
        assertRejected("certificate chain", () -> verifier(Instant.parse("2021-02-01T00:00:00Z")).verify(attestation, CHALLENGE));
    }

    @Test
    public void rejectsChainNotIssuedByConfiguredRoot() throws Exception {
        // Trust only the sample's own credential certificate: the chain then no longer leads to the root
        Map<?, ?> object = (Map<?, ?>) CborReader.decodeSingle(Base64.getDecoder().decode(attestation));
        byte[] credCert = (byte[]) ((List<?>) ((Map<?, ?>) object.get("attStmt")).get("x5c")).get(0);
        X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(credCert));
        Path pem = Files.createTempFile("not-apple-root", ".pem");
        Files.writeString(pem, "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder().encodeToString(leaf.getEncoded())
                + "\n-----END CERTIFICATE-----\n");
        properties.getIos().setRootCaPath(pem.toString());
        try {
            assertRejected("certificate chain", () -> verify(attestation, CHALLENGE));
        } finally {
            Files.deleteIfExists(pem);
        }
    }

    @Test
    public void rejectsTamperedAuthenticatorData() {
        byte[] bytes = Base64.getDecoder().decode(attestation);
        Map<?, ?> object = (Map<?, ?>) CborReader.decodeSingle(bytes);
        byte[] authData = (byte[]) object.get("authData");
        int at = indexOf(bytes, authData);
        bytes[at + 36] ^= 0x01; // counter's last byte: 0 -> 1
        assertRejected("nonce mismatch", () -> verify(Base64.getEncoder().encodeToString(bytes), CHALLENGE));
    }

    @Test
    public void rejectsNonCbor() {
        assertRejected("not valid CBOR", () -> verify(Base64.getEncoder().encodeToString("not cbor".getBytes()), CHALLENGE));
    }

    @Test
    public void rejectsNonBase64() {
        assertRejected("not base64", () -> verify("***", CHALLENGE));
    }

    @Test
    public void rejectsBlankAttestation() {
        assertRejected("missing", () -> verify(" ", CHALLENGE));
    }

    @Test
    public void rejectsWhenNotConfigured() {
        properties.getIos().setTeamId("");
        assertRejected("not configured", () -> verify(attestation, CHALLENGE));
    }

    @Test
    public void bundledRootIsAppleAppAttestationRootCa() {
        X509Certificate root = AppleAppAttestVerifier.loadRootCa(null);
        assertTrue(root.getSubjectX500Principal().getName().contains("CN=Apple App Attestation Root CA"));
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        throw new AssertionError("authData not found in attestation");
    }
}
