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
import io.mosip.mimoto.dto.dpop.DpopIssuanceSession;
import io.mosip.mimoto.exception.InvalidRequestException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
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
public class DpopProofService {

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

    public DpopIssuanceSession createSession(String state, String issuerId, String alg, String tokenHtu, String credentialHtu) {
        try {
            JWK privateJwk = generateKey(alg);
            String jkt = privateJwk.toPublicJWK().computeThumbprint().toString();
            return DpopIssuanceSession.builder()
                    .state(state)
                    .issuerId(issuerId)
                    .alg(alg)
                    .privateJwkJson(privateJwk.toJSONString())
                    .jkt(jkt)
                    .tokenHtu(normalizeHtu(tokenHtu))
                    .credentialHtu(normalizeHtu(credentialHtu))
                    .build();
        } catch (InvalidRequestException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Unable to create DPoP key");
        }
    }

    public String createProof(DpopIssuanceSession session, String htu, String htm, String nonce, String accessToken) {
        try {
            JWK privateJwk = JWK.parse(session.getPrivateJwkJson());
            JWSAlgorithm algorithm = JWSAlgorithm.parse(session.getAlg());
            JWSHeader header = new JWSHeader.Builder(algorithm)
                    .type(new JOSEObjectType("dpop+jwt"))
                    .jwk(privateJwk.toPublicJWK())
                    .build();
            Instant now = Instant.now();
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .jwtID(UUID.randomUUID().toString())
                    .claim("htm", htm.toUpperCase())
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
            jwt.sign(signer(privateJwk, algorithm));
            return jwt.serialize();
        } catch (Exception e) {
            log.error("Failed to sign DPoP proof for issuer {}", session.getIssuerId(), e);
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

    private static JWSSigner signer(JWK privateJwk, JWSAlgorithm algorithm) throws Exception {
        if (privateJwk instanceof RSAKey rsaKey) {
            return new RSASSASigner(rsaKey);
        }
        if (privateJwk instanceof ECKey ecKey) {
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
