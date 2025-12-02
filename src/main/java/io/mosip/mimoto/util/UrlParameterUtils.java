package io.mosip.mimoto.util;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class UrlParameterUtils {

    /**
     * Extracts a query parameter value from a URL using Apache URLEncodedUtils
     *
     * @param url           the URL to parse
     * @param parameterName the name of the parameter to extract
     * @return the decoded parameter value, or null if not found
     */
    public static String extractQueryParameter(String url, String parameterName) throws URISyntaxException {
        if (url == null || url.trim().isEmpty()) {
            return null;
        }

        URI uri = new URI(url);
        List<NameValuePair> params = URLEncodedUtils.parse(uri, StandardCharsets.UTF_8);

        for (NameValuePair param : params) {
            if (parameterName.equals(param.getName())) {
                return param.getValue();
            }
        }
        return null;
    }
}
