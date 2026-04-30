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
 * Algorithm handler for ES256K (ECDSA with SHA-256 using secp256k1 curve) signing.
 * Uses secp256k1 curve and requires BouncyCastle provider for key generation and signing.
 */
public class ES256KAlgorithmHandler implements SigningAlgorithmHandler {

    private static final String CURVE_NAME = SigningAlgorithmConstants.CURVE_SECP256K1;
    private static final String PROVIDER = SigningAlgorithmConstants.BC_PROVIDER;

    @Override
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(SigningAlgorithmConstants.EC, PROVIDER);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVE_NAME);
        generator.initialize(ecSpec);
        return generator.generateKeyPair();
    }

    @Override
    public KeyFactory getKeyFactory() throws NoSuchAlgorithmException, NoSuchProviderException {
        return KeyFactory.getInstance(SigningAlgorithmConstants.EC, PROVIDER);
    }

    @Override
    public JWK createJWK(KeyPair keyPair) {
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

        return new ECKey.Builder(Curve.SECP256K1, publicKey).privateKey(privateKey).algorithm(JWSAlgorithm.ES256K).keyUse(KeyUse.SIGNATURE).build();
    }

    @Override
    public JWSSigner createSigner(JWK jwk) throws JOSEException {
        ECDSASigner signer = new ECDSASigner((ECKey) jwk);
        signer.getJCAContext().setProvider(BouncyCastleProviderUtil.getProvider());
        return signer;
    }

}