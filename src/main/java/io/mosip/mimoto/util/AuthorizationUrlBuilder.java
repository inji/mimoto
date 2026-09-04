package io.mosip.mimoto.util;

import org.apache.commons.lang.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Builds the OpenID4VCI authorization request URL, matching
 * inji-vci-client {@code AuthorizationUrlBuilder}.
 */
public final class AuthorizationUrlBuilder {

    private AuthorizationUrlBuilder() {
    }

    public static String build(String authorizationEndpoint,
                               String clientId,
                               String redirectUri,
                               String scope,
                               String responseType,
                               String state,
                               String codeChallenge,
                               String codeChallengeMethod,
                               String uiLocales,
                               String dpopJkt) {
        if (StringUtils.isBlank(authorizationEndpoint)) {
            throw new IllegalArgumentException("authorization_endpoint cannot be blank");
        }
        StringBuilder url = new StringBuilder(authorizationEndpoint);
        url.append(authorizationEndpoint.contains("?") ? "&" : "?");
        url.append("client_id=").append(encode(clientId));
        url.append("&redirect_uri=").append(encode(redirectUri));
        url.append("&response_type=").append(encode(responseType));
        url.append("&scope=").append(encode(scope));
        url.append("&state=").append(encode(state));
        url.append("&code_challenge=").append(encode(codeChallenge));
        url.append("&code_challenge_method=").append(encode(codeChallengeMethod));
        if (StringUtils.isNotBlank(uiLocales)) {
            url.append("&ui_locales=").append(encode(uiLocales));
        }
        if (StringUtils.isNotBlank(dpopJkt)) {
            url.append("&dpop_jkt=").append(encode(dpopJkt));
        }
        return url.toString();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }
}
