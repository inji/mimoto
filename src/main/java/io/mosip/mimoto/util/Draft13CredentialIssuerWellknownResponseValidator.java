package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.mimoto.CredentialDefinitionResponseDto;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

@Slf4j
@Component
public class Draft13CredentialIssuerWellknownResponseValidator {

    public static final String MSO_MDOC = "mso_mdoc";
    public static final String LDP_VC = "ldp_vc";

    public void validate(CredentialIssuerWellKnownResponse response, Validator validator) throws InvalidWellknownResponseException {
        Set<ConstraintViolation<CredentialIssuerWellKnownResponse>> violations = validator.validate(response);
        if (!violations.isEmpty()) {
            StringBuilder sb = new StringBuilder("Validation failed:");
            for (ConstraintViolation<CredentialIssuerWellKnownResponse> violation : violations) {
                sb.append("\n").append(violation.getPropertyPath()).append(": ").append(violation.getMessage());
            }
            throw new InvalidWellknownResponseException(sb.toString());
        }

        Map<String, CredentialsSupportedResponse> validConfigs = new LinkedHashMap<>();
        for (Map.Entry<String, CredentialsSupportedResponse> entry : response.getCredentialConfigurationsSupported().entrySet()) {
            String key = entry.getKey();
            CredentialsSupportedResponse config = entry.getValue();
            try {
                if (config == null) {
                    throw new InvalidWellknownResponseException("Null credential configuration");
                }
                if (MSO_MDOC.equals(config.getFormat())) {
                    if (StringUtils.isBlank(config.getDoctype())) {
                        throw new InvalidWellknownResponseException("Mandatory field 'doctype' missing");
                    }
                }
                if (LDP_VC.equals(config.getFormat())) {
                    if (config.getCredentialDefinition() == null) {
                        throw new InvalidWellknownResponseException("credentialDefinition: must not be null");
                    }
                    Set<ConstraintViolation<CredentialDefinitionResponseDto>> credentialDefinitionViolations = validator.validate(config.getCredentialDefinition());
                    if (!credentialDefinitionViolations.isEmpty()) {
                        StringBuilder sb = new StringBuilder("Validation failed:");
                        for (ConstraintViolation<CredentialDefinitionResponseDto> violation : credentialDefinitionViolations) {
                            sb.append("\n").append(violation.getPropertyPath()).append(": ").append(violation.getMessage());
                        }
                        throw new InvalidWellknownResponseException(sb.toString());
                    }
                }
                validConfigs.put(key, config);
            } catch (InvalidWellknownResponseException e) {
                log.warn("Skipping invalid credential configuration '{}': {}", key, e.getMessage());
            }
        }
        if (!response.getCredentialConfigurationsSupported().isEmpty() && validConfigs.isEmpty()) {
            throw new InvalidWellknownResponseException("All credential configurations in issuer well-known are invalid");
        }
        response.setCredentialConfigurationsSupported(validConfigs);
    }
}
