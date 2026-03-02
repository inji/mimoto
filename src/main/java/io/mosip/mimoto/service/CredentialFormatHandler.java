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
     * Build format-specific fields in the credential request object
     */
    VCCredentialRequest buildCredentialRequest(VCCredentialRequestProof proof, CredentialsSupportedResponse credentialsSupportedResponse);

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
    Map<String, Object> extractAllCredentialProperties(VCCredentialResponse vcCredentialResponse);
}