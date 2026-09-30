package io.mosip.mimoto.util;

import com.nimbusds.jose.jwk.JWK;
import io.mosip.mimoto.constant.BindingMethod;
import io.mosip.mimoto.constant.SigningAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPair;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BindingMethodUtilTest {

    private BindingMethodUtil bindingMethodUtil;

    @BeforeEach
    void setUp() {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        bindingMethodUtil = new BindingMethodUtil();
        ReflectionTestUtils.setField(bindingMethodUtil, "bindingMethodsPriorityOrder", "jwk,did:jwk,did:key");
    }

    // --- selectBindingMethod ---

    @Test
    void selectBindingMethodReturnsJwkWhenIssuerSupportsIt() {
        assertEquals(BindingMethod.JWK, bindingMethodUtil.selectBindingMethod(List.of("jwk", "did:jwk")));
    }

    @Test
    void selectBindingMethodReturnsDidJwkWhenJwkNotInIssuerList() {
        assertEquals(BindingMethod.DID_JWK, bindingMethodUtil.selectBindingMethod(List.of("did:jwk", "did:key")));
    }

    @Test
    void selectBindingMethodReturnsDidKeyWhenOnlyDidKeyMatches() {
        assertEquals(BindingMethod.DID_KEY, bindingMethodUtil.selectBindingMethod(List.of("did:key")));
    }

    @Test
    void selectBindingMethodRespectsPriorityOrderNotIssuerOrder() {
        // Issuer lists did:key first, but wallet priority has did:jwk before did:key — must pick did:jwk
        assertEquals(BindingMethod.DID_JWK, bindingMethodUtil.selectBindingMethod(List.of("did:key", "did:jwk")));
    }

    @Test
    void selectBindingMethodFallsBackToDidJwkWhenIssuerListIsNull() {
        assertEquals(BindingMethod.DID_JWK, bindingMethodUtil.selectBindingMethod(null));
    }

    @Test
    void selectBindingMethodFallsBackToDidJwkWhenIssuerListIsEmpty() {
        assertEquals(BindingMethod.DID_JWK, bindingMethodUtil.selectBindingMethod(Collections.emptyList()));
    }

    @Test
    void selectBindingMethodFallsBackToDidJwkWhenNoOverlapWithPriorityList() {
        assertEquals(BindingMethod.DID_JWK, bindingMethodUtil.selectBindingMethod(List.of("unknown-method", "another-unsupported")));
    }

    // --- BindingMethod.fromString ---

    @Test
    void fromStringReturnsJwk() {
        assertEquals(BindingMethod.JWK, BindingMethod.fromString("jwk"));
    }

    @Test
    void fromStringReturnsDidJwk() {
        assertEquals(BindingMethod.DID_JWK, BindingMethod.fromString("did:jwk"));
    }

    @Test
    void fromStringReturnsDidKey() {
        assertEquals(BindingMethod.DID_KEY, BindingMethod.fromString("did:key"));
    }

    @Test
    void fromStringIsCaseInsensitive() {
        assertEquals(BindingMethod.JWK, BindingMethod.fromString("JWK"));
        assertEquals(BindingMethod.DID_JWK, BindingMethod.fromString("DID:JWK"));
        assertEquals(BindingMethod.DID_KEY, BindingMethod.fromString("DID:KEY"));
    }

    @Test
    void fromStringThrowsForUnknownValue() {
        assertThrows(IllegalArgumentException.class, () -> BindingMethod.fromString("unknown"));
    }

    // --- encodeDidJwk ---

    @Test
    void encodeDidJwkProducesCorrectFormatForEd25519() throws Exception {
        KeyPair keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.ED25519);
        JWK jwk = SigningKeyUtil.generateJwk(SigningAlgorithm.ED25519, keyPair);

        String result = BindingMethodUtil.encodeDidJwk(jwk);

        assertTrue(result.startsWith("did:jwk:"), "should start with did:jwk:");
        assertTrue(result.endsWith("#0"), "should end with #0");
        // middle part must be base64url (no +, /, =)
        String encoded = result.substring("did:jwk:".length(), result.length() - 2);
        assertFalse(encoded.isEmpty());
        assertFalse(encoded.contains("+"));
        assertFalse(encoded.contains("/"));
        assertFalse(encoded.contains("="));
    }

    // --- encodeDidKey ---

    @Test
    void encodeDidKeyForEd25519HasCorrectStructure() throws Exception {
        KeyPair keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.ED25519);
        JWK jwk = SigningKeyUtil.generateJwk(SigningAlgorithm.ED25519, keyPair);

        String result = BindingMethodUtil.encodeDidKey(jwk, SigningAlgorithm.ED25519);

        assertTrue(result.startsWith("did:key:z"), "should start with did:key:z");
        String identifier = result.substring("did:key:".length(), result.indexOf('#'));
        assertEquals("did:key:" + identifier + "#" + identifier, result, "fragment should repeat the identifier");
    }

    @Test
    void encodeDidKeyForEs256HasCorrectStructure() throws Exception {
        KeyPair keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.ES256);
        JWK jwk = SigningKeyUtil.generateJwk(SigningAlgorithm.ES256, keyPair);

        String result = BindingMethodUtil.encodeDidKey(jwk, SigningAlgorithm.ES256);

        assertTrue(result.startsWith("did:key:z"));
        String identifier = result.substring("did:key:".length(), result.indexOf('#'));
        assertEquals("did:key:" + identifier + "#" + identifier, result);
    }

    @Test
    void encodeDidKeyForRs256HasCorrectStructure() throws Exception {
        KeyPair keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.RS256);
        JWK jwk = SigningKeyUtil.generateJwk(SigningAlgorithm.RS256, keyPair);

        String result = BindingMethodUtil.encodeDidKey(jwk, SigningAlgorithm.RS256);

        assertTrue(result.startsWith("did:key:z"));
        String identifier = result.substring("did:key:".length(), result.indexOf('#'));
        assertEquals("did:key:" + identifier + "#" + identifier, result);
    }
}