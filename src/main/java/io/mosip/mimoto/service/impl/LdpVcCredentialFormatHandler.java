package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.service.CredentialFormatHandler;
import io.mosip.mimoto.util.LocaleUtils;
import static io.mosip.mimoto.util.IssuerConfigUtil.camelToTitleCase;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

@Slf4j
@Component("ldp_vc")
public class LdpVcCredentialFormatHandler implements CredentialFormatHandler {

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public String getSupportedFormat() {
        return CredentialFormat.LDP_VC.getFormat();
    }

    @Override
    public VCCredentialRequest buildCredentialRequest(VCCredentialRequestProof proof, CredentialsSupportedResponse credentialsSupportedResponse) {

        List<String> credentialContext = credentialsSupportedResponse.getCredentialDefinition().getContext();
        if (credentialContext == null || credentialContext.isEmpty()) {
            credentialContext = List.of("https://www.w3.org/2018/credentials/v1");
        }

        return VCCredentialRequest.builder().format(getSupportedFormat())
                .proof(proof)
                .credentialDefinition(VCCredentialDefinition.builder().type(credentialsSupportedResponse.getCredentialDefinition().getType()).context(credentialContext).build())
                .build();
    }

    @Override
    public Map<String, Object> extractCredentialClaims(VCCredentialResponse vcCredentialResponse) {
        VCCredentialProperties credential = objectMapper.convertValue(vcCredentialResponse.getCredential(), VCCredentialProperties.class);
        return (Map<String, Object>) credential.getCredentialSubject();
    }

    private void addFallbackDisplayProperties(
            Map<String, Object> credentialProperties,
            LinkedHashMap<String, CredentialIssuerDisplayResponse> localizedDisplayMap,
            String resolvedLocale) {
        // fallback for missing display properties from issuer well-known
        Set<String> credentialFields = credentialProperties.keySet();
        Set<String> missingDisplayFields = new HashSet<>(credentialFields);
        missingDisplayFields.removeAll(localizedDisplayMap.keySet());
        // remove metadata fields that are not part of the display properties
        missingDisplayFields.remove("id");

        // Generate fallbacks for fields without well-known display properties
        for (String missingField : missingDisplayFields) {
            String displayName = camelToTitleCase(missingField);

            CredentialIssuerDisplayResponse fallbackDisplay = new CredentialIssuerDisplayResponse();
            fallbackDisplay.setName(displayName);
            fallbackDisplay.setLocale("en");

            localizedDisplayMap.put(missingField, fallbackDisplay);
        }
    }

    @Override
    public LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> loadDisplayPropertiesFromWellknown(
            Map<String, Object> credentialProperties,
            CredentialsSupportedResponse credentialsSupportedResponse,
            String userLocale) {

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = new LinkedHashMap<>();
        List<String> orderedKeys = credentialsSupportedResponse.getOrder();

        // LDP VC format — display config is in "credential_definition.credential_subject"
        if (credentialsSupportedResponse.getCredentialDefinition() == null ||
                credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject() == null) {
            log.info("Issuer well-known has no credential definition or credential subject for LDP VC format; falling back to claim-based display properties");
            return buildFallbackDisplayProperties(credentialProperties, orderedKeys, userLocale);
        }

        Map<String, CredentialDisplayResponseDto> displayConfigMap =
                credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject();

        if (displayConfigMap == null) {
            log.info("No display configuration found in issuer well-known for LDP VC format; falling back to claim-based display properties");
            return buildFallbackDisplayProperties(credentialProperties, orderedKeys, userLocale);
        }

        String resolvedLocale = LocaleUtils.resolveLocaleWithFallback(displayConfigMap, userLocale);

        LinkedHashMap<String, CredentialIssuerDisplayResponse> localizedDisplayMap = new LinkedHashMap<>();

        if (resolvedLocale != null) {
            displayConfigMap.forEach((key, dto) -> {
                dto.getDisplay().stream()
                        .filter(display -> LocaleUtils.matchesLocale(display.getLocale(), resolvedLocale))
                        .findFirst()
                        .ifPresent(display -> localizedDisplayMap.put(key, display));
            });
        }

        addFallbackDisplayProperties(credentialProperties, localizedDisplayMap, resolvedLocale);

        List<String> fieldKeys = (orderedKeys != null && !orderedKeys.isEmpty())
                ? orderedKeys
                : new ArrayList<>(localizedDisplayMap.keySet());

        for (String key : fieldKeys) {
            CredentialIssuerDisplayResponse display = localizedDisplayMap.get(key);
            Object value = credentialProperties.get(key);
            if (display != null && value != null) {
                displayProperties.put(key, Map.of(display, value));
            }
        }

        return displayProperties;
    }

    private LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> buildFallbackDisplayProperties(
            Map<String, Object> credentialProperties,
            List<String> orderedKeys, String userLocale) {

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = new LinkedHashMap<>();

        // Determine field order (prefer issuer-provided 'order' if any)
        List<String> fieldKeys = (orderedKeys != null && !orderedKeys.isEmpty())
                ? new ArrayList<>(orderedKeys)
                : new ArrayList<>(credentialProperties.keySet());

        // Exclude non-claim metadata
        fieldKeys.remove("id");

        // Build default display entries from claims
        for (String key : fieldKeys) {
            Object value = credentialProperties.get(key);
            if (value == null) {
                continue;
            }

            CredentialIssuerDisplayResponse display = null;

            // Check if value is a Map containing display information
            if (value instanceof Map) {
                Map<String, Object> valueMap = (Map<String, Object>) value;
                Object displayObj = valueMap.get("display");

                if (displayObj instanceof List) {
                    List<Map<String, Object>> displayList = (List<Map<String, Object>>) displayObj;

                    if (!displayList.isEmpty()) {
                        // Try to find matching locale
                        Optional<Map<String, Object>> matchingDisplay = displayList.stream()
                                .filter(d -> LocaleUtils.matchesLocale((String) d.get("locale"), userLocale))
                                .findFirst();

                        Map<String, Object> selectedDisplay = matchingDisplay.orElse(displayList.get(0));

                        display = new CredentialIssuerDisplayResponse();
                        display.setName((String) selectedDisplay.get("name"));
                        display.setLocale((String) selectedDisplay.get("locale"));
                    }
                }
            }

            // Fallback to default display if no nested display found
            if (display == null) {
                display = new CredentialIssuerDisplayResponse();
                display.setName(camelToTitleCase(key));
                display.setLocale("en");
            }

            displayProperties.put(key, Map.of(display, value));
        }

        return displayProperties;
    }
}
