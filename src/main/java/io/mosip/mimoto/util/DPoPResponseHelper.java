package io.mosip.mimoto.util;

import io.mosip.mimoto.constant.DPoPConstants;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;

/**
 * Reads RFC 9449 {@code DPoP-Nonce} and {@code use_dpop_nonce} challenges.
 */
public final class DPoPResponseHelper {

    private DPoPResponseHelper() {
    }

    public static boolean isUseDPoPNonce(HttpHeaders headers, String responseBody) {
        String wwwAuthenticate = headers == null ? null : headers.getFirst(HttpHeaders.WWW_AUTHENTICATE);
        WwwAuthenticateChallenge challenge = WwwAuthenticateChallenge.parse(wwwAuthenticate);
        if (challenge.isDPoP() && DPoPConstants.USE_DPOP_NONCE_ERROR.equals(challenge.getError())) {
            return true;
        }
        return StringUtils.isNotBlank(responseBody) && responseBody.contains(DPoPConstants.USE_DPOP_NONCE_ERROR);
    }

    public static String dPoPNonce(HttpHeaders headers) {
        if (headers == null || headers.isEmpty()) {
            return null;
        }
        String nonce = headers.getFirst(DPoPConstants.DPOP_NONCE_HEADER);
        return StringUtils.isNotBlank(nonce) ? nonce : null;
    }
}
