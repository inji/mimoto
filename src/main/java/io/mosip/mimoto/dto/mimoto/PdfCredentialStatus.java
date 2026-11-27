package io.mosip.mimoto.dto.mimoto;

import io.mosip.mimoto.model.CredentialStatusCheck;
import lombok.Value;

import java.util.List;

@Value
public class PdfCredentialStatus {
    List<CredentialStatusCheck> statusChecks;
    Boolean expired;

    public static PdfCredentialStatus of(List<CredentialStatusCheck> statusChecks, Boolean expired) {
        return new PdfCredentialStatus(statusChecks == null ? List.of() : statusChecks, expired);
    }

    public String displayValue() {
        if (hasInvalidPurpose("revocation")) {
            return "Revoked";
        }
        if (hasInvalidPurpose("suspension")) {
            return "Suspended";
        }
        if (Boolean.TRUE.equals(expired)) {
            return "Expired";
        }
        return "Valid";
    }

    private boolean hasInvalidPurpose(String purpose) {
        return statusChecks != null && statusChecks.stream()
                .anyMatch(check -> purpose.equalsIgnoreCase(check.getPurpose()) && !check.isValid());
    }
}
