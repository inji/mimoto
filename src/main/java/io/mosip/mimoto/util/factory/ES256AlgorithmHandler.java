package io.mosip.mimoto.util.factory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import io.mosip.mimoto.constant.SigningAlgorithmConstants;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

/**
 * Algorithm handler for ES256 (ECDSA with SHA-256) signing.
 * Uses secp256r1 (P-256) curve and BouncyCastle provider for signing operations.
 */
public class ES256AlgorithmHandler implements SigningAlgorithmHandler {

    @Override
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(SigningAlgorithmConstants.EC);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(SigningAlgorithmConstants.CURVE_SECP256R1);
        generator.initialize(ecSpec);
        return generator.generateKeyPair();
    }

    @Override
    public KeyFactory getKeyFactory() throws NoSuchAlgorithmException {
        return KeyFactory.getInstance(SigningAlgorithmConstants.EC);
    }

    @Override
    public JWK createJWK(KeyPair keyPair) {
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

        return new ECKey.Builder(Curve.P_256, publicKey).privateKey(privateKey).algorithm(JWSAlgorithm.ES256).keyUse(KeyUse.SIGNATURE).build();
    }

    @Override
    public JWSSigner createSigner(JWK jwk) throws JOSEException {
        ECDSASigner signer = new ECDSASigner((ECKey) jwk);
        signer.getJCAContext().setProvider(BouncyCastleProviderUtil.getProvider());
        return signer;
    }

}