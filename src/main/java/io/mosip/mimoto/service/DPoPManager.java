package io.mosip.mimoto.service;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.mimoto.constant.DPoPConstants;
import io.mosip.mimoto.dto.dpop.DPoPSession;
import io.mosip.mimoto.exception.InvalidRequestException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;

/**
 * Creates ephemeral DPoP keys and signs RFC 9449 proofs.
 * Algorithm is the first value in {@code dpop_signing_alg_values_supported} that Mimoto can sign.
 * When that metadata is absent or empty, the default is ES256.
 */
@Service
@Slf4j
public class DPoPManager {

    static final List<String> SUPPORTED_ALGS = List.of("RS256", "PS256", "ES256");
    private static final String DEFAULT_ALG = "ES256";
    private static final int RSA_KEY_SIZE = 2048;
    private static final long PROOF_TTL_SECONDS = 60;

    public String selectAlgorithm(List<String> supportedAlgs) {
        if (supportedAlgs == null || supportedAlgs.isEmpty()) {
            return DEFAULT_ALG;
        }
        for (String advertised : supportedAlgs) {
            if (StringUtils.isBlank(advertised)) {
                continue;
            }
            for (String supported : SUPPORTED_ALGS) {
                if (supported.equalsIgnoreCase(advertised.trim())) {
                    return supported;
                }
            }
        }
        throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                "No mutually supported DPoP algorithm. Server supports: " + supportedAlgs);
    }

    public DPoPSession createSession(String state, String alg, String tokenEndpoint) {
        try {
            JWK jwk = generateKey(alg);
            return DPoPSession.builder()
                    .state(state)
                    .alg(alg)
                    .jwkJson(jwk.toJSONString())
                    .tokenHtu(normalizeHtu(tokenEndpoint))
                    .build();
        } catch (InvalidRequestException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Unable to create DPoP key");
        }
    }

    public String jwkThumbprint(DPoPSession session) {
        try {
            return JWK.parse(session.getJwkJson()).toPublicJWK().computeThumbprint().toString();
        } catch (Exception e) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Unable to compute DPoP JWK thumbprint");
        }
    }

    public String generateTokenProof(DPoPSession session) {
        return generateTokenProof(session, null);
    }

    public String generateTokenProof(DPoPSession session, String nonce) {
        return buildProof(session, session.getTokenHtu(), nonce, null);
    }

    public String generateCredentialProof(DPoPSession session, String credentialEndpoint, String accessToken) {
        return generateCredentialProof(session, credentialEndpoint, accessToken, null);
    }

    public String generateCredentialProof(DPoPSession session, String credentialEndpoint, String accessToken,
                                          String nonce) {
        if (StringUtils.isNotBlank(nonce)) {
            session.setIssuerDPoPNonce(nonce);
        }
        return buildProof(session, credentialEndpoint, session.getIssuerDPoPNonce(), accessToken);
    }

    private String buildProof(DPoPSession session, String htu, String nonce, String accessToken) {
        try {
            JWK jwk = JWK.parse(session.getJwkJson());
            JWSAlgorithm algorithm = JWSAlgorithm.parse(session.getAlg());
            JWSHeader header = new JWSHeader.Builder(algorithm)
                    .type(new JOSEObjectType("dpop+jwt"))
                    .jwk(jwk.toPublicJWK())
                    .build();
            Instant now = Instant.now();
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .jwtID(UUID.randomUUID().toString())
                    .claim("htm", DPoPConstants.HTTP_METHOD_POST)
                    .claim("htu", normalizeHtu(htu))
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(PROOF_TTL_SECONDS)));
            if (StringUtils.isNotBlank(nonce)) {
                claims.claim("nonce", nonce);
            }
            if (StringUtils.isNotBlank(accessToken)) {
                claims.claim("ath", accessTokenHash(accessToken));
            }
            SignedJWT jwt = new SignedJWT(header, claims.build());
            jwt.sign(signer(jwk, algorithm));
            return jwt.serialize();
        } catch (Exception e) {
            log.error("Failed to sign DPoP proof", e);
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Unable to sign DPoP proof");
        }
    }

    public static String normalizeHtu(String endpoint) {
        URI uri = URI.create(endpoint);
        String path = uri.getRawPath();
        if (path == null || path.isBlank()) {
            path = "/";
        }
        return URI.create(uri.getScheme() + "://" + uri.getAuthority() + path).normalize().toString();
    }

    private static JWK generateKey(String alg) throws Exception {
        return switch (alg) {
            case "RS256" -> new RSAKeyGenerator(RSA_KEY_SIZE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
            case "PS256" -> new RSAKeyGenerator(RSA_KEY_SIZE)
                    .algorithm(JWSAlgorithm.PS256)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
            case "ES256" -> new ECKeyGenerator(Curve.P_256)
                    .algorithm(JWSAlgorithm.ES256)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
            default -> throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                    "Unsupported DPoP algorithm: " + alg);
        };
    }

    private static JWSSigner signer(JWK jwk, JWSAlgorithm algorithm) throws Exception {
        if (jwk instanceof RSAKey rsaKey) {
            return new RSASSASigner(rsaKey);
        }
        if (jwk instanceof ECKey ecKey) {
            return new ECDSASigner(ecKey);
        }
        throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Unsupported DPoP key type: " + algorithm);
    }

    private static String accessTokenHash(String accessToken) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.US_ASCII));
        return Base64URL.encode(hash).toString();
    }
}
