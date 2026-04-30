package io.mosip.mimoto.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.X509CertUtils;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.mimoto.JwkDto;
import io.mosip.mimoto.dto.mimoto.WalletBindingInternalResponseDto;
import io.mosip.mimoto.dto.mimoto.WalletBindingResponseDto;
import io.mosip.mimoto.exception.IssuerOnboardingException;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jws.JsonWebSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
public class JoseUtil {
    private static final String BEGIN_KEY = "-----BEGIN PUBLIC KEY-----";
    private static final String END_KEY = "-----END PUBLIC KEY-----";
    private static final String ALG_RS256 = "RS256";

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private P12KeyStoreManager p12KeyStoreManager;

    public static JwkDto getJwkFromPublicKey(String publicKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {

        RSAPublicKeySpec keySpec = publicKeyString.startsWith(BEGIN_KEY) ? getKeySpecForPublicKey(publicKeyString) : getKeySpecForRSAKey(publicKeyString);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        // Convert to JWK format
        JWK jwk = new RSAKey.Builder((RSAPublicKey)publicKey)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .build();

        JwkDto jwkDto = new JwkDto(jwk.getKeyType().toString(), ((RSAKey) jwk).getPublicExponent().toString(), ((RSAKey) jwk).getModulus().toString());
        return jwkDto;

    }

    private static RSAPublicKeySpec getKeySpecForRSAKey(String publicKeyString) {
        String key = publicKeyString.replace("\n", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "");

        org.bouncycastle.asn1.pkcs.RSAPublicKey pkcs1PublicKey = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(CryptoUtil.decodePlainBase64(key));
        BigInteger modulus = pkcs1PublicKey.getModulus();
        BigInteger publicExponent = pkcs1PublicKey.getPublicExponent();
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
        return keySpec;

    }

    private static RSAPublicKeySpec getKeySpecForPublicKey(String publicKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String key = publicKeyString.replace("\n", "")
                .replace(BEGIN_KEY, "")
                .replace(END_KEY, "");
        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(CryptoUtil.decodePlainBase64(key));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey generatePublic = (RSAPublicKey) kf.generatePublic(spec);
        BigInteger modulus = generatePublic.getModulus();
        BigInteger exponent = generatePublic.getPublicExponent();
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
        return keySpec;
    }


    public ResponseWrapper<WalletBindingResponseDto> addThumbprintAndKeyId(ResponseWrapper<WalletBindingInternalResponseDto> responseDto) {

        log.debug("Inside addThumbprintAndKeyId ");

        ResponseWrapper<WalletBindingResponseDto> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setErrors(responseDto.getErrors());

        try {
            if (responseDto.getResponse() != null) {
                WalletBindingInternalResponseDto resp = mapper.readValue(
                        mapper.writeValueAsString(responseDto.getResponse()), WalletBindingInternalResponseDto.class);
                // generate thumbprint and key id
                String certificate = resp.getCertificate();
                X509Certificate x509Certificate = X509CertUtils.parse(certificate);
                JsonWebSignature jwSign = new JsonWebSignature();
                jwSign.setKeyIdHeaderValue(x509Certificate.getSerialNumber().toString(10));
                jwSign.setX509CertSha256ThumbprintHeaderValue(x509Certificate);

                // map fields with thumbprint and key id
                WalletBindingResponseDto response = new WalletBindingResponseDto();
                response.setCertificate(resp.getCertificate());
                response.setEncryptedWalletBindingId(resp.getWalletUserId());
                response.setExpireDateTime(resp.getExpireDateTime());
                response.setKeyId(jwSign.getKeyIdHeaderValue());
                response.setThumbprint(jwSign.getX509CertSha256ThumbprintHeaderValue());

                responseWrapper.setResponse(response);
            }
        } catch (Exception e) {
            log.error("Exception occured while setting thumbprint ", e);
        }

        return responseWrapper;
    }

    public String getJWT(String clientId, String keyStorePath, String fileName, String alias, String cyptoPassword, String audience) throws IssuerOnboardingException, IOException {

        Map<String, Object> header = new HashMap<>();
        header.put("alg", ALG_RS256);

        String keyStorePathWithFileName = keyStorePath + fileName;
        Date issuedAt = Date.from(Instant.now());
        Date expiresAt = Date.from(Instant.now().plusMillis(120000));
        RSAPrivateKey privateKey = null;
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = p12KeyStoreManager.loadP12(keyStorePathWithFileName, alias, cyptoPassword);
            if(privateKeyEntry == null){
                throw new IssuerOnboardingException("Private Key Entry is Missing for the alias " + alias);
            }
            privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();
        } catch (IOException e) {
           log.error("Exception happened while loading the p12 file for invoking token call.");
           throw e;
        }
        return JWT.create()
                .withHeader(header)
                .withIssuer(clientId)
                .withSubject(clientId)
                .withAudience(audience)
                .withExpiresAt(expiresAt)
                .withIssuedAt(issuedAt)
                .withClaim("jti", UUID.randomUUID().toString())
                .sign(Algorithm.RSA256(null, privateKey));
    }

    public String generateJwt(String audience, String clientId, String cNonce) throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        RSAKey jwk = new RSAKey.Builder((RSAPublicKey) kp.getPublic())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();

        Map<String, Object> header = new HashMap<>();
        header.put("alg", ALG_RS256);
        header.put("typ", "openid4vci-proof+jwt");
        header.put("jwk", jwk.getRequiredParams());

        Date issuedAt = Date.from(Instant.now());
        Date expiresAt = Date.from(Instant.now().plusMillis(120000000));
        RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();

        Map<String, Object> payload = new HashMap<>();
        payload.put("sub", clientId);
        payload.put("aud", audience);
        payload.put("nonce", cNonce);
        payload.put("iss", clientId);
        payload.put("exp", expiresAt.toInstant().getEpochSecond());
        payload.put("iat", issuedAt.toInstant().getEpochSecond());
        payload.put("jti", UUID.randomUUID().toString());

        return Jwts.builder()
                .setHeader(header)
                .setIssuer(clientId)
                .setSubject(clientId)
                .setAudience(audience)
                .setExpiration(expiresAt)
                .setIssuedAt(issuedAt)
                .setClaims(payload)
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }
}
