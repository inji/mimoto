package io.mosip.mimoto.util;

import com.fasterxml.jackson.databind.JsonNode;
import io.mosip.mimoto.constant.VCSpecificationVersion;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class VCSpecVersionDetector {

    private static final String NONCE_ENDPOINT = "nonce_endpoint";
    private static final String CREDENTIAL_CONFIGURATIONS_SUPPORTED = "credential_configurations_supported";
    private static final String CREDENTIAL_METADATA = "credential_metadata";
    private static final String DISPLAY = "display";

    public VCSpecificationVersion detectVersion(JsonNode wellknownResponse) {
        if (wellknownResponse.has(VCSpecVersionDetector.NONCE_ENDPOINT) && !wellknownResponse.get(VCSpecVersionDetector.NONCE_ENDPOINT).asText().isBlank()) {
            log.debug("Detected V1 specification version: nonce_endpoint field present");
            return VCSpecificationVersion.V1;
        }

        JsonNode configurationsSupported = wellknownResponse.get(CREDENTIAL_CONFIGURATIONS_SUPPORTED);
        if (configurationsSupported != null && configurationsSupported.isObject()) {
            for (JsonNode config : configurationsSupported) {
                if (config.has(CREDENTIAL_METADATA)) {
                    log.debug("Detected V1 specification version: credential_metadata found in credential configuration");
                    return VCSpecificationVersion.V1;
                }
            }

            for (JsonNode config : configurationsSupported) {
                if (config.has(DISPLAY)) {
                    log.debug("Detected Draft-13 specification version: display found in credential configuration");
                    return VCSpecificationVersion.DRAFT_13;
                }
            }
        }

        log.debug("Defaulting to V1 specification version");
        return VCSpecificationVersion.V1;
    }
}
