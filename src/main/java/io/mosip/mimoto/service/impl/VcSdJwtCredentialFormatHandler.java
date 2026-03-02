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
    public Map<String, Object> extractAllCredentialProperties(VCCredentialResponse vcCredentialResponse) {
        Object credential = vcCredentialResponse.getCredential();
        if (credential instanceof String) {
            return extractAllPropertiesFromSdJwt((String) credential);
        }
        return Collections.emptyMap();
    }

    public Map<String, Object> extractClaimsFromSdJwt(String sdJwtString) {
        try {
            SDJWT sdJwt = SDJWT.parse(sdJwtString);
            Map<String, Object> claims = new LinkedHashMap<>();

            // Parse JWT payload
            String credentialJwt = sdJwt.getCredentialJwt();
            if (credentialJwt != null) {
                Map<String, Object> jwtPayload = parseJwtPayload(credentialJwt);
                if (jwtPayload != null) {
                    claims.putAll(jwtPayload);
                }
            }

            // Add disclosures
            List<Disclosure> disclosures = sdJwt.getDisclosures();
            if (disclosures != null && !disclosures.isEmpty()) {
                for (Disclosure disclosure : disclosures) {
                    try {
                        String claimName = disclosure.getClaimName();
                        Object claimValue = disclosure.getClaimValue();

                        if (claimName != null && claimValue != null) {
                            claims.put(claimName, claimValue); // Add directly to claims
                        }
                    } catch (Exception e) {
                        log.warn("Failed to process disclosure: {}", e.getMessage());
                    }
                }
            }

            // Remove standard JWT claims and SD-JWT metadata
            List<String> metadataKeys = Arrays.asList("vct", "cnf", "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "_sd", "_sd_alg", "id");
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

    public Map<String, Object> extractAllPropertiesFromSdJwt(String sdJwtString) {
        //TODO: Temporary usage of hardcoded sd-jwt string for testing; replace with actual input from vcCredentialResponse
        sdJwtString = "eyJ4NXQjUzI1NiI6InAxRkpsRGl2V09xdG96MjczcUxQRnp3OWc1ZUU1SUtlMUlzbUxEaktCTmMiLCJ4NWMiOlsiTUlJREVEQ0NBZmlnQXdJQkFnSUlsR2pIQ0UrSjhHc3dEUVlKS29aSWh2Y05BUUVMQlFBd2VERUxNQWtHQTFVRUJoTUNTVTR4Q3pBSkJnTlZCQWdNQWt0Qk1SSXdFQVlEVlFRSERBbENRVTVIUVV4UFVrVXhEakFNQmdOVkJBb01CVWxKU1ZSQ01SY3dGUVlEVlFRTERBNUZXRUZOVUV4RkxVTkZUbFJGVWpFZk1CMEdBMVVFQXd3V2QzZDNMbVY0WVcxd2JHVXVZMjl0SUNoU1QwOVVLVEFlRncweU5UQTFNekF3T0RBNU5UUmFGdzB5T0RBMU1qa3dPREE1TlRSYU1JR2JNUXN3Q1FZRFZRUUdFd0pKVGpFTE1Ba0dBMVVFQ0F3Q1MwRXhFakFRQmdOVkJBY01DVUpCVGtkQlRFOVNSVEVPTUF3R0ExVUVDZ3dGU1VsSlZFSXhGekFWQmdOVkJBc01Ea1ZZUVUxUVRFVXRRMFZPVkVWU01VSXdRQVlEVlFRREREbDNkM2N1WlhoaGJYQnNaUzVqYjIwZ0tFTkZVbFJKUmxsZlZrTmZVMGxIVGw5RlExOVNNUzFGUTE5VFJVTlFNalUyVWpGZlUwbEhUaWt3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVRXbEdCaFZzZndPMUtqMUtvMm9jd1FQbzROdXFqU0haMDQ3emlNdDFqM0hsLyt1OWxmWGZZTUtPRDc4Ymg2Q3A5SFltRXlrOGo5R3lDOG50OFQ4THVEbzBVd1F6QVNCZ05WSFJNQkFmOEVDREFHQVFIL0FnRUJNQjBHQTFVZERnUVdCQlNMWFBmb21nNWdMYXo4bVJFT09welVlU3dKVGpBT0JnTlZIUThCQWY4RUJBTUNBb1F3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUN4S2w2dU8vcXp4VjdYZFl0K1dFSms3MkhnSC95a3ZvS3VKRmo2d0tHbDZuNWt6V29jcldBNW5LclhkcytmbWxGd3ordUZSQjhCSzlBNGZpVnprWmYvRTI3clVHYS9GZkJqenhVL1JXeE1aV01KYUw2MkkxSHhZYmhMRTB4ZFNteFJHU0RHbThreVl0V2VpeTJzWTVMSGE5eEdIc1R0NTdDYVE5MStjSUhNQlBvWlFWbUlZWklibm4yVzA0QklPbDh4UFphMk45ZXRmZTg1K3JuNzNhTjZCekpJT1h6bG5kTzhoTU5GVFl0V2JCOUpyMGdmdmdYa2o2Yndwb0FnY1NBeDBaOXUzM0M0TFRjaEhaYlF5cWRSRkVlMnVUQm1vMWF6NGF2andxK01OSHRsS1ZhMmt6d0xlZnJ5aWpuaUQ5RnpFN0RtdThGN3FKQWVVNHByeG83cz0iLCJNSUlEdHpDQ0FwK2dBd0lCQWdJSVNGaVV1NkZDNEtBd0RRWUpLb1pJaHZjTkFRRUxCUUF3ZURFTE1Ba0dBMVVFQmhNQ1NVNHhDekFKQmdOVkJBZ01Ba3RCTVJJd0VBWURWUVFIREFsQ1FVNUhRVXhQVWtVeERqQU1CZ05WQkFvTUJVbEpTVlJDTVJjd0ZRWURWUVFMREE1RldFRk5VRXhGTFVORlRsUkZVakVmTUIwR0ExVUVBd3dXZDNkM0xtVjRZVzF3YkdVdVkyOXRJQ2hTVDA5VUtUQWVGdzB5TlRBMU16QXdPREE0TkRGYUZ3MHpNekExTWpnd09EQTROREZhTUhneEN6QUpCZ05WQkFZVEFrbE9NUXN3Q1FZRFZRUUlEQUpMUVRFU01CQUdBMVVFQnd3SlFrRk9SMEZNVDFKRk1RNHdEQVlEVlFRS0RBVkpTVWxVUWpFWE1CVUdBMVVFQ3d3T1JWaEJUVkJNUlMxRFJVNVVSVkl4SHpBZEJnTlZCQU1NRm5kM2R5NWxlR0Z0Y0d4bExtTnZiU0FvVWs5UFZDa3dnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDeTFvQldsSC9QWEFjdGFwL0crNlhoR0txUDhZVkVqOWlwcEd0QlA3QXoxRnVzUFVtMG1ScFcwZUN6ckJtRlVnQkl5V0VqU055MWp1NXNFUEJaQVFxSVJwQ1NYUXRVWCs0WHpQeGg0eENWbVNqMHV3WHdpSGJiZVFyRy9EWGRNenFMNkJnbWoxQS9PbGZnRkhEaXM0dDJ6VWJmQVZ3ek1WSkkvdE9kRzk1T2I3b09hVS9oS3pJUzBpQUttbHQyUEQwSGlVK3h6MWZjcnVuazMzVDRxVGgrZEw4U0M3dzNMQ1hMK0N5ai8wZjI2MXJtQlFJblRMaHpaZ2pudk5ZWWFRSEJKM3UxWFc1eEdCN0lEUTBwbngyS0RHT2dIczFMeE90V2ZXM201cDRydGhucFNnamF0eFg5NWpCRGQvR2dsQXhPMldqTkZqRDkyVGZjdG80NEcydmZBZ01CQUFHalJUQkRNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUl3SFFZRFZSME9CQllFRkRnSkdtUlRoV0pQWW9UamoxOU15aXlLOXNGNU1BNEdBMVVkRHdFQi93UUVBd0lDaERBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQXBrRmpXUFNhS1lwblRaVEJQbWlNT09TOWUvL24yNEJZQXA0ZFhaN04zaDc2bmYreFdCbXVFS0pOUVZhdE11M0NZdCtveDVRQkw0Rmoyd0ZRc3lhY3BDbkdCZHZKSksySkY3TmxPL1IwTXk1dTBHblU3bjRJelBtT2xVOUVSSHFPN3g4SDNQQzl1OEJ1dGxwaWxxN3hLSXpzMVo3S0VZK1FZcGh6SmRxeHJVSWRFR3VQcnZzYTZSc0pwdTJPdGxFSzZRREhINjBCV1Jha29pN3BIdCtVQ1FCWTNyM0x5UFBCWDQzWkN5MXM2ZFFicDJxOTRrUWhtVXR1c0RjUnMrcXBPdzFYd01YRDJTa1RzbXlWVnhhNDVWV3pnU0k1RzdNTUpSVW9XOTZ2RHRjM0Z1K2NkSG5OcHM1M05CY3MwOHNQVVgwTXU2VHZJY2dkRk9ydTlSOXY1dz09Il0sImtpZCI6Imh0dHBzOi8vaW5qaWNlcnRpZnktbW9jay5kZXYtaW50LWluamkubW9zaXAubmV0I2IteUZjWDNsYkRIOTZlUVVtVVlIVFlLNXk1VkUweW1KeG11LTFDZ01fQVkiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpc3N1YW5jZURhdGUiOiIyMDI1LTA4LTA3VDEzOjI0OjUxLjU3OVoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJWSUQiOjEyMzQ1NiwiZ2VuZGVyIjp7Il9zZCI6WyJDSTkwd1U1MkpLZmM2bEVkcHVRWFVQSm9pN2JLbmJ6aVFEZ2E4NzdkQ21VIl19LCJwcm92aW5jZSI6W3sibGFuZ3VhZ2UiOiJmcmEiLCJ2YWx1ZSI6Inl1xIFuIDIifSx7Imxhbmd1YWdlIjoiYXJhIiwidmFsdWUiOiLZitmO2Y_Yp9mG6omb4qWNIn0seyJsYW5ndWFnZSI6ImVuZyIsInZhbHVlIjoieXVhbiB3ZWUifV0sInBvc3RhbENvZGUiOjQ1MDA5LCJmdWxsTmFtZSI6eyJfc2QiOlsienF4ZHZhcmxPSFA5MmlCZjZzMmlnVE9DQnY2akpYNW9kbGJtOW5vMllaOCJdfSwiaWQiOiJkaWQ6andrOmV5SnJkSGtpT2lKUFMxQWlMQ0oxYzJVaU9pSnphV2NpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklrbDBVa2xqU21kYWVUVjFSMVJUZURWMU5IWmlTRnB2TWxKYVZXWlpUVWhJT0ZSdmNVWlJkRU01VDI4aWZRPT0iLCJVSU4iOjEyMzQ1NiwicmVnaW9uIjpbeyJsYW5ndWFnZSI6ImZyYSIsInZhbHVlIjoieXXEgW4gMyJ9LHsibGFuZ3VhZ2UiOiJhcmEiLCJ2YWx1ZSI6IiTZhNmP2Ybar--Al-GGkSJ9LHsibGFuZ3VhZ2UiOiJlbmciLCJ2YWx1ZSI6Inl1YW4gd2VlIDMifV0sImVtYWlsIjoic2l3ZXIua21AZ21haWwuY29tIiwiX3NkIjpbIlk5Y1lFdjNMSWkzX1loRHFIaVpRY3gwQUVBZGdtQ0VvdTRtTnZWbGNCZzgiLCJpQ253MXV2azFuLXlmd0dxU1J2amFwc2RIMGtpay1sY2h4U3RUSzlfREEwIl19LCJ2Y3QiOiJTZF9qd3RfbGFuZHN0YXRlbWVudCIsImlzcyI6Imh0dHBzOi8vaW5qaWNlcnRpZnktbW9jay5kZXYtaW50LWluamkubW9zaXAubmV0IiwiY25mIjp7ImtpZCI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpQUzFBaUxDSjFjMlVpT2lKemFXY2lMQ0pqY25ZaU9pSkZaREkxTlRFNUlpd2llQ0k2SWtsMFVrbGpTbWRhZVRWMVIxUlRlRFYxTkhaaVNGcHZNbEphVldaWlRVaElPRlJ2Y1VaUmRFTTVUMjhpZlE9PSJ9LCJ0eXBlIjpbeyJfdmFsdWUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiX3ZhbHVlIjoiTW9ja1ZlcmlmaWFibGVDcmVkZW50aWFsIn1dLCJAY29udGV4dCI6W3siX3ZhbHVlIjoiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEifSx7Il92YWx1ZSI6Imh0dHBzOi8vdmhhcnNoLmdpdGh1Yi5pby9ESUQvbW9jay1jb250ZXh0Lmpzb24ifV0sImlzc3VlciI6ImRpZDp3ZWI6bW9zaXAuZ2l0aHViLmlvOmluamktY29uZmlnOmNvbGxhYjptb2NrLWlkZW50aXR5IiwiZXhwaXJhdGlvbkRhdGUiOiIyMDI3LTA4LTA3VDEzOjI0OjUxLjU3OVoifQ.FgX_E1VoIl8gdT2XYs9I_d3muejRF9uJYMuO8Y5E65FBxWv8QDw6W5sFdw86kpUwHFA7eqv4t0bqjBHOv89UBw~WyJqYU9zX3ZqMDJxWUpubmRMMWdlUlBRIiwiZ2VuZGVyIixbeyJsYW5ndWFnZSI6ImVuZyIsInZhbHVlIjoiZmVtYWxlIn0seyJsYW5ndWFnZSI6ImZyYSIsInZhbHVlIjoiZmVNw6JsZSJ9LHsibGFuZ3VhZ2UiOiJhcmEiLCJ2YWx1ZSI6Itiw2YPYsSJ9XV0~WyJ4STNlLU1OdkZhblRIY3pIRVJ3LXJ3IiwicGhvbmUiLCIrOTE5NDI3MzU3OTM0Il0~WyJpVy0xTDFPV2ZKM0VuYlFxY3RGT1V3IiwiZnVsbE5hbWUiLFt7Imxhbmd1YWdlIjoiZnJhIiwidmFsdWUiOiJBbGhlcmkgQm9iYnkifSx7Imxhbmd1YWdlIjoiYXJhIiwidmFsdWUiOiLYqtiq2q_ZhNiv2YPZhtiz2Y7YstmC2YfZkNmC2ZDZgdmEINiv2LPZitmK2LPZitmD2K_Zg9mG2YjapNmIIn0seyJsYW5ndWFnZSI6ImVuZyIsInZhbHVlIjoiQWxoZXJpIEJvYmJ5In1dXQ~WyJWamxIUVk5Q3BELTNaOU9PVXM2WlR3IiwiZGF0ZU9mQmlydGgiLCIxOTk5LzEwLzIxIl0~";
        try {
            SDJWT sdJwt = SDJWT.parse(sdJwtString);
            Map<String, Object> claims = new LinkedHashMap<>();

            // Parse JWT payload
            String credentialJwt = sdJwt.getCredentialJwt();
            if (credentialJwt != null) {
                Map<String, Object> jwtPayload = parseJwtPayload(credentialJwt);
                if (jwtPayload != null) {
                    claims.putAll(jwtPayload);
                }
            }

            // Add disclosures
            List<Disclosure> disclosures = sdJwt.getDisclosures();
            if (disclosures != null && !disclosures.isEmpty()) {
                for (Disclosure disclosure : disclosures) {
                    try {
                        String claimName = disclosure.getClaimName();
                        Object claimValue = disclosure.getClaimValue();

                        if (claimName != null && claimValue != null) {
                            claims.put(claimName, claimValue); // Add directly to claims
                        }
                    } catch (Exception e) {
                        log.warn("Failed to process disclosure: {}", e.getMessage());
                    }
                }
            }

            return claims;

        } catch (IllegalArgumentException e) {
            log.error("Error parsing SD-JWT with Authlete library: {}", e.getMessage(), e);
            return Collections.emptyMap();
        } catch (Exception e) {
            log.error("Unexpected error processing SD-JWT", e);
            return Collections.emptyMap();
        }
    }

    private LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> buildFallbackDisplayProperties(
            Map<String, Object> credentialProperties,
            Set<String> orderedKeys) {

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