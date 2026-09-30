package io.mosip.mimoto.util;

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
public class V1CredentialIssuerWellknownResponseValidator {
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
                    if (CollectionUtils.isEmpty(config.getDisplay())) {
                        throw new InvalidWellknownResponseException("Mandatory field 'display' missing for V1 ldp_vc");
                    }
                    if (CollectionUtils.isEmpty(config.getClaims())) {
                        throw new InvalidWellknownResponseException("Mandatory field 'claims' missing for V1 ldp_vc");
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
