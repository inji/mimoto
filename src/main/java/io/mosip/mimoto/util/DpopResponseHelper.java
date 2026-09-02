package io.mosip.mimoto.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.DpopConstants;
import io.mosip.mimoto.exception.DpopChallengeException;
import org.apache.commons.lang.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helpers for propagating DPoP-related HTTP headers to browser clients.
 */
public final class DpopResponseHelper {

    public static final String EXPOSED_DPOP_HEADERS =
            DpopConstants.DPOP_NONCE_HEADER + ", " + DpopConstants.WWW_AUTHENTICATE_HEADER;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Pattern XML_TAG = Pattern.compile("<([a-zA-Z0-9_]+)>([^<]*)</\\1>");

    private DpopResponseHelper() {
    }

    public static ResponseEntity<Object> challengeResponse(DpopChallengeException exception) {
        HttpHeaders headers = copyForwardableChallengeHeaders(exception.getResponseHeaders());
        headers.set(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, EXPOSED_DPOP_HEADERS);

        Object body = parseChallengeBody(exception.getResponseBody());
        return ResponseEntity.status(exception.getStatusCode())
                .headers(headers)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    public static HttpHeaders copyForwardableChallengeHeaders(HttpHeaders source) {
        HttpHeaders headers = new HttpHeaders();
        if (source == null) {
            return headers;
        }
        String nonce = source.getFirst(DpopConstants.DPOP_NONCE_HEADER);
        String wwwAuthenticate = source.getFirst(DpopConstants.WWW_AUTHENTICATE_HEADER);
        if (nonce != null) {
            headers.set(DpopConstants.DPOP_NONCE_HEADER, nonce);
        }
        if (wwwAuthenticate != null) {
            headers.set(DpopConstants.WWW_AUTHENTICATE_HEADER, wwwAuthenticate);
        }
        return headers;
    }

    /**
     * MOSIP eSignet may serialize {@code OAuthError} as XML. Inji Web retries
     * {@code use_dpop_nonce} only when the body has a JSON {@code error} field.
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

    private static Object parseChallengeBody(String responseBody) {
        if (StringUtils.isBlank(responseBody)) {
            return Map.of();
        }
        Object xmlError = normalizeOAuthErrorBody(responseBody);
        if (xmlError instanceof Map) {
            return xmlError;
        }
        try {
            return OBJECT_MAPPER.readValue(responseBody, new TypeReference<Map<String, Object>>() {});
        } catch (JsonProcessingException e) {
            return responseBody;
        }
    }

}
