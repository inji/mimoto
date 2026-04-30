package io.mosip.mimoto.util;

import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

@Slf4j
public class JwtUtils {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(JwtUtils.class);

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static Map<String, Object> extractJwtPayloadFromSdJwt(String sdJwtString) {
        if (StringUtils.isBlank(sdJwtString)) {
            return null;
        } else {
            String[] elements = sdJwtString.split("~", -1);
            return parseJwtPayload(elements[0]);
        }
    }

    public static Map<String, Object> parseJwtPayload(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 3) {
                log.error("Invalid JWT format for payload parsing: ");
                return Collections.emptyMap();
            }
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            return objectMapper.readValue(payloadJson, Map.class);
        } catch (Exception e) {
            log.error("Error parsing JWT payload", e);
            return Collections.emptyMap();
        }
    }

    /**
     * Extracts the JWT header as a Map.
     */
    public static Map<String, Object> parseJwtHeader(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 3) {
                log.warn("Invalid JWT format for header parsing: ");
                return Collections.emptyMap();
            }
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            return objectMapper.readValue(headerJson, Map.class);
        } catch (Exception e) {
            log.error("Error parsing JWT header", e);
            return Collections.emptyMap();
        }
    }
}
