package io.mosip.mimoto.util;

import org.apache.commons.lang.StringUtils;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Normalizes authorization-server OAuth error bodies for BFF token exchange.
 */
public final class DpopResponseHelper {

    private static final Pattern XML_TAG = Pattern.compile("<([a-zA-Z0-9_]+)>([^<]*)</\\1>");

    private DpopResponseHelper() {
    }

    /**
     * MOSIP eSignet may serialize {@code OAuthError} as XML. BFF token exchange
     * treats {@code use_dpop_nonce} when the body has an {@code error} field.
     */
    public static Object normalizeOAuthErrorBody(String responseBody) {
        if (StringUtils.isBlank(responseBody)) {
            return responseBody;
        }
        Map<String, String> xmlError = parseOAuthErrorXml(responseBody);
        return xmlError != null ? xmlError : responseBody;
    }

    static Map<String, String> parseOAuthErrorXml(String responseBody) {
        if (StringUtils.isBlank(responseBody) || !responseBody.contains("<error>")) {
            return null;
        }
        Map<String, String> tags = new LinkedHashMap<>();
        Matcher matcher = XML_TAG.matcher(responseBody);
        while (matcher.find()) {
            tags.put(matcher.group(1), matcher.group(2));
        }
        String error = tags.get("error");
        if (StringUtils.isBlank(error)) {
            return null;
        }
        Map<String, String> result = new LinkedHashMap<>();
        result.put("error", error);
        if (tags.containsKey("error_description")) {
            result.put("error_description", tags.get("error_description"));
        }
        return result;
    }
}
