package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.Set;

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

        for (CredentialsSupportedResponse supportedCredentialConfiguration : response.getCredentialConfigurationsSupported().values()) {
            if (MSO_MDOC.equals(supportedCredentialConfiguration.getFormat())) {
                if (StringUtils.isBlank(supportedCredentialConfiguration.getDoctype())) {
                    throw new InvalidWellknownResponseException("Mandatory field 'doctype' missing");
                }
                if (CollectionUtils.isEmpty(supportedCredentialConfiguration.getClaims())) {
                    throw new InvalidWellknownResponseException("Mandatory field 'claims' missing");
                }
            }

            if (LDP_VC.equals(supportedCredentialConfiguration.getFormat())) {
                if (CollectionUtils.isEmpty(supportedCredentialConfiguration.getDisplay())) {
                    throw new InvalidWellknownResponseException("Mandatory field 'display' missing for V1 ldp_vc");
                }
                if (CollectionUtils.isEmpty(supportedCredentialConfiguration.getClaims())) {
                    throw new InvalidWellknownResponseException("Mandatory field 'claims' missing for V1 ldp_vc");
                }
            }
        }
    }
}
