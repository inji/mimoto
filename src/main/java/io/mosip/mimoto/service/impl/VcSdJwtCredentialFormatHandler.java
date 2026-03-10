package io.mosip.mimoto.service.impl;


import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.service.CredentialFormatHandler;
import io.mosip.mimoto.util.LocaleUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

import static io.mosip.mimoto.util.IssuerConfigUtil.camelToTitleCase;
import static io.mosip.mimoto.util.JwtUtils.parseJwtPayload;

@Slf4j
@Component("vc+sd-jwt")
public class VcSdJwtCredentialFormatHandler implements CredentialFormatHandler {

    private static final String KEY = "...";
    private static final String SD = "_sd";

    private final ObjectMapper objectMapper;

    public VcSdJwtCredentialFormatHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public String getSupportedFormat() {
        return CredentialFormat.VC_SD_JWT.getFormat();
    }


    @Override
    public VCCredentialRequest buildCredentialRequest(VCCredentialRequestProof proof, CredentialsSupportedResponse credentialsSupportedResponse) {
        return VCCredentialRequest.builder().format(getSupportedFormat()).proof(proof).vct(credentialsSupportedResponse.getVct()).build();
    }

    @Override
    public Map<String, Object> extractCredentialClaims(VCCredentialResponse vcCredentialResponse) {
        Object credential = vcCredentialResponse.getCredential();
        if (credential instanceof String) {
            return extractClaimsFromSdJwt((String) credential);
        }
        log.warn("Unexpected credential format in response for SD-JWT VC:");
        return Collections.emptyMap();
    }

    @Override
    public LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> loadDisplayPropertiesFromWellknown(
            Map<String, Object> credentialProperties,
            CredentialsSupportedResponse credentialsSupportedResponse,
            String userLocale) {

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = new LinkedHashMap<>();

        // Start with ordered fields
        Set<String> orderedKeys = Optional.ofNullable(credentialsSupportedResponse.getOrder())
                .map(LinkedHashSet::new) // preserve order
                .orElse(new LinkedHashSet<>());

        // Add remaining keys from credentialProperties that are not already in orderedKeys
        for (String key : credentialProperties.keySet()) {
            orderedKeys.add(key); // Set ensures no duplicates
        }

        if (credentialsSupportedResponse.getClaims() == null || credentialsSupportedResponse.getClaims().isEmpty()) {
            log.info("Issuer well-known has no claims for SD-JWT format; falling back to claim-based display properties");
            return buildFallbackDisplayProperties(credentialProperties, orderedKeys);
        }

        // Extract raw claims and convert to DTOs
        Map<String, Object> rawClaims = Optional.ofNullable(credentialsSupportedResponse.getClaims())
                .map(map -> (map.size() == 1 && map.values().iterator().next() instanceof Map)
                        ? (Map<String, Object>) map.values().iterator().next()
                        : map)
                .orElse(Collections.emptyMap());

        Map<String, CredentialDisplayResponseDto> convertedClaimsMap = rawClaims.entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> objectMapper.convertValue(entry.getValue(), CredentialDisplayResponseDto.class)
                ));

        if (convertedClaimsMap.isEmpty()) {
            log.info("No display configuration found for SD-JWT format");
            return buildFallbackDisplayProperties(credentialProperties, orderedKeys);
        }

        String resolvedLocale = LocaleUtils.resolveLocaleWithFallback(convertedClaimsMap, userLocale);
        LinkedHashMap<String, CredentialIssuerDisplayResponse> localizedDisplayMap = new LinkedHashMap<>();

        if (resolvedLocale != null) {
            convertedClaimsMap.forEach((key, dto) -> {
                dto.getDisplay().stream()
                        .filter(display -> LocaleUtils.matchesLocale(display.getLocale(), resolvedLocale))
                        .findFirst()
                        .ifPresent(display -> localizedDisplayMap.put(key, display));
            });
        }

        for (String key : orderedKeys) {
            Object value = credentialProperties.get(key);
            if (value == null) {
                continue; // Skip fields without a value
            }

            CredentialIssuerDisplayResponse display = localizedDisplayMap.get(key);

            // Fallback if not found in metadata
            if (display == null) {
                display = new CredentialIssuerDisplayResponse();
                display.setName(camelToTitleCase(key));
                display.setLocale("en");
            }

            displayProperties.put(key, Map.of(display, value));
        }

        return displayProperties;
    }

    @Override
    public Map<String, Map<String, Object>> extractAllCredentialProperties(VCCredentialResponse vcCredentialResponse) {
        Object credential = vcCredentialResponse.getCredential();
        if (credential instanceof String) {
            return extractAllPropertiesFromSdJwt((String) credential);
        }
        return Collections.emptyMap();
    }

    public Map<String, Object> extractClaimsFromSdJwt(String sdJwtString) {
        try {
            SDJWT sdJwt = SDJWT.parse(sdJwtString);

            // Extract public claims from the credential JWT
            Map<String, Object> claims = extractPublicClaims(sdJwt);

            // Extract disclosures and merge with claims
            Map<String, Object> sdClaims = extractSdClaims(sdJwt);
            claims.putAll(sdClaims);

            // Remove standard JWT claims and SD-JWT metadata
            List<String> metadataKeys = Arrays.asList("vct", "cnf", "iss", "sub", "aud", "exp", "nbf", "iat", "jti", SD, "_sd_alg", "id");
            metadataKeys.forEach(claims::remove);

            // Return claims directly as result
            return claims;

        } catch (IllegalArgumentException e) {
            log.error("Error parsing SD-JWT with Authlete library: {}", e.getMessage(), e);
            return Collections.emptyMap();
        } catch (Exception e) {
            log.error("Unexpected error processing SD-JWT", e);
            return Collections.emptyMap();
        }
    }

    public Map<String, Map<String, Object>> extractAllPropertiesFromSdJwt(String sdJwtString) {
        try {
            SDJWT sdJwt = SDJWT.parse(sdJwtString);

            Map<String, Map<String, Object>> claims = new LinkedHashMap<>();

            // Extract public claims from the credential JWT
            claims.put("publicClaims", extractPublicClaims(sdJwt));

            // Extract disclosures and merge with claims
            claims.put("sdClaims", extractSdClaimsForOVP(sdJwt));

            return claims;

        } catch (IllegalArgumentException e) {
            log.error("Error parsing SD-JWT with Authlete library: {}", e.getMessage(), e);
            return Collections.emptyMap();
        } catch (Exception e) {
            log.error("Unexpected error processing SD-JWT", e);
            return Collections.emptyMap();
        }
    }

    private Map<String, Object> extractPublicClaims(SDJWT sdJwt) {
        String credentialJwt = sdJwt.getCredentialJwt();
        Map<String, Object> publicClaims = new LinkedHashMap<>();
        if (credentialJwt != null) {
            Map<String, Object> jwtPayload = parseJwtPayload(credentialJwt);
            if (jwtPayload != null) {
                publicClaims.putAll(jwtPayload);
            }
        }
        return publicClaims;
    }

    private Map<String, Object> extractSdClaims(SDJWT sdJwt) {
        Map<String, Object> sdClaims = new LinkedHashMap<>();
        List<Disclosure> disclosures = sdJwt.getDisclosures();
        if (disclosures != null && !disclosures.isEmpty()) {
            for (Disclosure disclosure : disclosures) {
                try {
                    String claimName = disclosure.getClaimName();
                    Object claimValue = disclosure.getClaimValue();

                    if (claimName != null && claimValue != null) {
                        sdClaims.put(claimName, claimValue);
                    }
                } catch (Exception e) {
                    log.warn("Failed to process disclosure: {}", e.getMessage());
                }
            }
        }
        return sdClaims;
    }

    private Map<String, Object> extractSdClaimsForOVP(SDJWT sdJwt) {
        Map<String, Disclosure> digestToDisclosure = new HashMap<>();
        Map<String, String> digestToDisclosureB64 = new HashMap<>();
        List<Disclosure> disclosures = sdJwt.getDisclosures();
        if (disclosures != null) {
            for (Disclosure disclosure : disclosures) {
                String digest = disclosure.digest();
                digestToDisclosure.put(digest, disclosure);
                digestToDisclosureB64.put(digest, disclosure.getDisclosure());
            }
        }

        String credentialJwt = sdJwt.getCredentialJwt();
        Map<String, Object> payload = parseJwtPayload(credentialJwt);
        if (payload == null || payload.isEmpty()) {
            return Collections.emptyMap();
        }

        Map<String, Object> pathToDisclosures = new LinkedHashMap<>();
        resolveDisclosures(payload, "", Collections.emptyList(), digestToDisclosure, digestToDisclosureB64, pathToDisclosures);
        return pathToDisclosures;
    }

    private void resolveDisclosures(Object value, String path, List<String> parentDisclosures, Map<String, Disclosure> digestToDisclosure, Map<String, String> digestToDisclosureB64, Map<String, Object> pathToDisclosures) {
        if (value instanceof List) {
            List<Object> list = (List<Object>) value;
            for (int i = 0; i < list.size(); i++) {
                Object item = list.get(i);
                String currentPath = path + "[" + i + "]";
                if (item instanceof Map) {
                    Map<String, Object> mapItem = (Map<String, Object>) item;
                    if (mapItem.size() == 1 && mapItem.containsKey(KEY)) {
                        String digest = (String) mapItem.get(KEY);
                        Disclosure disclosure = digestToDisclosure.get(digest);
                        if (disclosure != null) {
                            List<String> currentDisclosures = new ArrayList<>(parentDisclosures);
                            currentDisclosures.add(digestToDisclosureB64.get(digest));
                            pathToDisclosures.put(currentPath, currentDisclosures);
                            resolveDisclosures(disclosure.getClaimValue(), currentPath, currentDisclosures, digestToDisclosure, digestToDisclosureB64, pathToDisclosures);
                        }
                        continue;
                    }
                }
                resolveDisclosures(item, currentPath, parentDisclosures, digestToDisclosure, digestToDisclosureB64, pathToDisclosures);
            }
            return;
        }

        if (value instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) value;

            Object sdDigestsObj = map.get(SD);
            if (sdDigestsObj instanceof List) {
                for (Object digestObj : (List<Object>) sdDigestsObj) {
                    String digest = (String) digestObj;
                    Disclosure disclosure = digestToDisclosure.get(digest);
                    if (disclosure == null || disclosure.getClaimName() == null) continue;
                    String claimName = disclosure.getClaimName();
                    if (SD.equals(claimName) || KEY.equals(claimName)) continue;

                    String fullPath = path.isEmpty() ? claimName : path + "." + claimName;
                    List<String> currentDisclosures = new ArrayList<>(parentDisclosures);
                    currentDisclosures.add(digestToDisclosureB64.get(digest));
                    pathToDisclosures.put(fullPath, currentDisclosures);
                    resolveDisclosures(disclosure.getClaimValue(), fullPath, currentDisclosures, digestToDisclosure, digestToDisclosureB64, pathToDisclosures);
                }
            }

            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (SD.equals(entry.getKey())) continue;
                String fullPath = path.isEmpty() ? entry.getKey() : path + "." + entry.getKey();
                resolveDisclosures(entry.getValue(), fullPath, parentDisclosures, digestToDisclosure, digestToDisclosureB64, pathToDisclosures);
            }
        }
    }

    private LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> buildFallbackDisplayProperties(Map<String, Object> credentialProperties, Set<String> orderedKeys) {
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = new LinkedHashMap<>();

        // Use ordered keys from parameter (already includes all fields)
        List<String> fieldKeys = new ArrayList<>(orderedKeys);

        fieldKeys.remove("id");

        // Build default display entries from claims
        for (String key : fieldKeys) {
            Object value = credentialProperties.get(key);
            if (value == null) {
                continue;
            }

            // Generate fallback display using claims keys
            CredentialIssuerDisplayResponse display = new CredentialIssuerDisplayResponse();
            display.setName(camelToTitleCase(key));
            display.setLocale("en");

            displayProperties.put(key, Map.of(display, value));
        }
        return displayProperties;
    }
}