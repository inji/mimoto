package io.mosip.mimoto.dto.mimoto;

import io.mosip.mimoto.model.CredentialStatusCheck;
import lombok.Value;

import java.util.List;

@Value
public class CredentialVerificationResult {
    List<CredentialStatusCheck> statusChecks;
    boolean expired;

    public CredentialVerificationResult(List<CredentialStatusCheck> statusChecks, boolean expired) {
        this.statusChecks = statusChecks;
        this.expired = expired;
    }
}
