package io.mosip.mimoto.util.factory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import io.mosip.mimoto.constant.SigningAlgorithmConstants;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

/**
 * Algorithm handler for Ed25519 (Edwards-curve Digital Signature Algorithm) signing.
 * Uses Ed25519 curve and implements custom JWSSigner with BouncyCastle for signing operations.
 */
public class Ed25519AlgorithmHandler implements SigningAlgorithmHandler {

    private static final int ED25519_KEY_SIZE_BYTES = 32;

    @Override
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(SigningAlgorithmConstants.ED25519);
        return generator.generateKeyPair();
    }

    @Override
    public KeyFactory getKeyFactory() throws NoSuchAlgorithmException {
        return KeyFactory.getInstance(SigningAlgorithmConstants.ED25519);
    }

    @Override
    public JWK createJWK(KeyPair keyPair) {
        EdECPublicKey edECPublicKey = (EdECPublicKey) keyPair.getPublic();
        EdECPrivateKey edECPrivateKey = (EdECPrivateKey) keyPair.getPrivate();

        byte[] x = Arrays.copyOfRange(edECPublicKey.getEncoded(), edECPublicKey.getEncoded().length - ED25519_KEY_SIZE_BYTES, edECPublicKey.getEncoded().length);
        byte[] d = Arrays.copyOfRange(edECPrivateKey.getEncoded(), edECPrivateKey.getEncoded().length - ED25519_KEY_SIZE_BYTES, edECPrivateKey.getEncoded().length);

        return new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(x)).d(Base64URL.encode(d)).algorithm(JWSAlgorithm.Ed25519).keyUse(KeyUse.SIGNATURE).build();
    }

    @Override
    public JWSSigner createSigner(JWK jwk) throws JOSEException {
        OctetKeyPair okp = (OctetKeyPair) jwk;
        byte[] privateKeyBytes = okp.getD().decode();

        return new JWSSigner() {
            private final JCAContext jcaContext = new JCAContext();

            @Override
            public Base64URL sign(JWSHeader header, byte[] input) throws JOSEException {
                try {
                    Ed25519Signer signer = new Ed25519Signer();
                    signer.init(true, new Ed25519PrivateKeyParameters(privateKeyBytes, 0));
                    signer.update(input, 0, input.length);
                    return Base64URL.encode(signer.generateSignature());
                } catch (Exception e) {
                    throw new JOSEException("Ed25519 signing failed", e);
                }
            }

            @Override
            public Set<JWSAlgorithm> supportedJWSAlgorithms() {
                return Collections.singleton(JWSAlgorithm.Ed25519);
            }

            @Override
            public JCAContext getJCAContext() {
                return jcaContext;
            }
        };
    }

}