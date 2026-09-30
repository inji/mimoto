package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.service.CredentialFormatHandler;
import io.mosip.mimoto.util.LocaleUtils;
import io.mosip.pixelpass.PixelPass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

import static io.mosip.mimoto.util.IssuerConfigUtil.toTitleCase;

/**
 * Format handler for ISO 18013-5 mdoc credentials (format {@code mso_mdoc}).
 * <p>
 * An issued mdoc arrives as a base64url-encoded CBOR string of shape
 * {@code { docType, issuerSigned: { nameSpaces: { <namespace>: [ IssuerSignedItem ] }, issuerAuth } }}.
 * We decode the CBOR to JSON via PixelPass, then flatten each {@code IssuerSignedItem}'s
 * {@code elementIdentifier -> elementValue} into a claims map for display/storage.
 * <p>
 * Note: PixelPass decodes text claims correctly but may corrupt binary values (e.g. {@code portrait}).
 * If that surfaces in testing, switch the decode here to {@code co.nstant.in.cbor} directly.
 */
@Slf4j
@Component("mso_mdoc")
public class MsoMdocCredentialFormatHandler implements CredentialFormatHandler {

    private static final String ISSUER_SIGNED = "issuerSigned";
    private static final String NAME_SPACES = "nameSpaces";
    private static final String ELEMENT_IDENTIFIER = "elementIdentifier";
    private static final String ELEMENT_VALUE = "elementValue";

    private final ObjectMapper objectMapper;
    private final PixelPass pixelPass;

    public MsoMdocCredentialFormatHandler(ObjectMapper objectMapper, PixelPass pixelPass) {
        this.objectMapper = objectMapper;
        this.pixelPass = pixelPass;
    }

    @Override
    public String getSupportedFormat() {
        return CredentialFormat.MSO_MDOC.getFormat();
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> extractCredentialClaims(VCCredentialResponse vcCredentialResponse) {
        Object credential = vcCredentialResponse.getCredential();
        if (!(credential instanceof String)) {
            log.warn("Unexpected credential type for mso_mdoc; expected base64url CBOR String");
            return Collections.emptyMap();
        }
        try {
            // PixelPass: base64url CBOR -> JSON; parse via Jackson to avoid a direct org.json dependency
            Object json = pixelPass.toJson(((String) credential).trim());
            if (json == null) {
                log.warn("mso_mdoc credential did not decode (PixelPass returned null)");
                return Collections.emptyMap();
            }
            Map<String, Object> root = objectMapper.readValue(json.toString(), new TypeReference<Map<String, Object>>() {});

            // nameSpaces may sit under issuerSigned, or (defensively) at the top level
            Object issuerSigned = root.get(ISSUER_SIGNED);
            Map<String, Object> nsHolder = (issuerSigned instanceof Map) ? (Map<String, Object>) issuerSigned : root;

            Object nameSpacesObj = nsHolder.get(NAME_SPACES);
            if (!(nameSpacesObj instanceof Map)) {
                log.warn("mso_mdoc credential has no nameSpaces map");
                return Collections.emptyMap();
            }
            Map<String, Object> nameSpaces = (Map<String, Object>) nameSpacesObj;

            Map<String, Object> claims = new LinkedHashMap<>();
            for (Object nsValue : nameSpaces.values()) {
                if (!(nsValue instanceof List)) {
                    continue;
                }
                for (Object itemObj : (List<?>) nsValue) {
                    if (itemObj instanceof Map) {
                        Map<?, ?> item = (Map<?, ?>) itemObj;
                        Object id = item.get(ELEMENT_IDENTIFIER);
                        if (id != null) {
                            claims.put(String.valueOf(id), item.get(ELEMENT_VALUE));
                        }
                    }
                }
            }
            return claims;
        } catch (Exception e) {
            log.error("Failed to decode mso_mdoc credential", e);
            return Collections.emptyMap();
        }
    }

    @Override
    public LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> loadDisplayPropertiesFromWellknown(
            Map<String, Object> credentialProperties,
            CredentialsSupportedResponse credentialsSupportedResponse,
            String userLocale) {

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = new LinkedHashMap<>();

        // Preserve issuer-provided order, then append any remaining claim keys
        Set<String> orderedKeys = Optional.ofNullable(credentialsSupportedResponse.getOrder())
                .map(LinkedHashSet::new)
                .orElse(new LinkedHashSet<>());
        orderedKeys.addAll(credentialProperties.keySet());

        if (credentialsSupportedResponse.getClaims() == null || credentialsSupportedResponse.getClaims().isEmpty()) {
            log.info("Issuer well-known has no claims for mso_mdoc format; falling back to claim-based display properties");
            return buildFallbackDisplayProperties(credentialProperties, orderedKeys);
        }

        // mso_mdoc claims are namespace-nested: { "<namespace>": { "<claim>": {display:[...]}, ... }, ... }
        // Flatten all namespaces into one claim map so keys align with the flattened claim identifiers
        // produced by extractCredentialClaims. Mirrors that method's multi-namespace handling.
        Map<String, Object> rawClaims = credentialsSupportedResponse.getClaims().entrySet().stream()
                .filter(e -> e.getValue() instanceof Map)
                .flatMap(e -> ((Map<String, Object>) e.getValue()).entrySet().stream())
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (a, b) -> a,
                        LinkedHashMap::new
                ));

        Map<String, CredentialDisplayResponseDto> convertedClaimsMap = rawClaims.entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> {
                            Object value = entry.getValue();
                            if (value instanceof List) {
                                // MDL wellknown: claim display is a direct array [{name, locale}]
                                CredentialDisplayResponseDto dto = new CredentialDisplayResponseDto();
                                dto.setDisplay(objectMapper.convertValue(value,
                                        new TypeReference<List<CredentialIssuerDisplayResponse>>() {}));
                                return dto;
                            }
                            return objectMapper.convertValue(value, CredentialDisplayResponseDto.class);
                        },
                        (a, b) -> a,
                        LinkedHashMap::new
                ));

        if (convertedClaimsMap.isEmpty()) {
            log.info("No display configuration found for mso_mdoc format");
            return buildFallbackDisplayProperties(credentialProperties, orderedKeys);
        }

        String resolvedLocale = LocaleUtils.resolveLocaleWithFallback(convertedClaimsMap, userLocale);
        LinkedHashMap<String, CredentialIssuerDisplayResponse> localizedDisplayMap = new LinkedHashMap<>();

        if (resolvedLocale != null) {
            convertedClaimsMap.forEach((key, dto) ->
                    dto.getDisplay().stream()
                            .filter(display -> LocaleUtils.matchesLocale(display.getLocale(), resolvedLocale))
                            .findFirst()
                            .ifPresent(display -> localizedDisplayMap.put(key, display)));
        }

        for (String key : orderedKeys) {
            Object value = credentialProperties.get(key);
            if (value == null) {
                continue;
            }
            CredentialIssuerDisplayResponse display = localizedDisplayMap.get(key);
            if (display == null) {
                display = new CredentialIssuerDisplayResponse();
                display.setName(toTitleCase(key));
                display.setLocale("en");
            }
            displayProperties.put(key, Map.of(display, value));
        }

        return displayProperties;
    }

    @Override
    public Map<String, Object> extractAllCredentialProperties(VCCredentialResponse vcCredentialResponse) {
        return extractCredentialClaims(vcCredentialResponse);
    }

    private LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> buildFallbackDisplayProperties(
            Map<String, Object> credentialProperties, Set<String> orderedKeys) {

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = new LinkedHashMap<>();
        List<String> fieldKeys = new ArrayList<>(orderedKeys);
        fieldKeys.remove("id");

        for (String key : fieldKeys) {
            Object value = credentialProperties.get(key);
            if (value == null) {
                continue;
            }
            CredentialIssuerDisplayResponse display = new CredentialIssuerDisplayResponse();
            display.setName(toTitleCase(key));
            display.setLocale("en");
            displayProperties.put(key, Map.of(display, value));
        }
        return displayProperties;
    }
}
