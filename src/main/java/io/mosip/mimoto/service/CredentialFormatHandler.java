package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.mimoto.*;

import java.util.LinkedHashMap;
import java.util.Map;

public interface CredentialFormatHandler {

    /**
     * Get the supported format for this processor
     */
    String getSupportedFormat();

    /**
     * Extract credential subject properties from VC response
     */
    Map<String, Object> extractCredentialClaims(VCCredentialResponse vcCredentialResponse);

    /**
     * Load display properties from well-known configuration
     */
    LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> loadDisplayPropertiesFromWellknown(
            Map<String, Object> credentialProperties,
            CredentialsSupportedResponse credentialsSupportedResponse,
            String userLocale);

    /**
     * Extract all properties from the Credential
     */
    Map<String, ?> extractAllCredentialProperties(VCCredentialResponse vcCredentialResponse);
}