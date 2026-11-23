package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.CredentialVerificationResult;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.exception.CredentialStatusException;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.model.CredentialStatusCheck;
import io.mosip.mimoto.service.CredentialVerifierService;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.CredentialStatusResult;
import io.mosip.vercred.vcverifier.data.CredentialVerificationSummary;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static io.mosip.mimoto.exception.ErrorConstants.CREDENTIAL_STATUS_UNAVAILABLE;

@Slf4j
@Service
public class CredentialVerifierServiceImpl implements CredentialVerifierService {

    private final ObjectMapper objectMapper;

    private final CredentialsVerifier credentialsVerifier;

    private final List<String> defaultStatusPurposeList;

    public CredentialVerifierServiceImpl(ObjectMapper objectMapper, CredentialsVerifier credentialsVerifier,
                                         @Value("${mosip.inji.credential.status.purpose-list:revocation,suspension}")
                                         List<String> defaultStatusPurposeList) {
        this.objectMapper = objectMapper;
        this.credentialsVerifier = credentialsVerifier;
        this.defaultStatusPurposeList = defaultStatusPurposeList;
    }

    @Override
    public CredentialVerificationResult verify(VCCredentialResponse response, List<String> statusPurposeList)
            throws JsonProcessingException, VCVerificationException {
        String credentialString = response.getCredential() instanceof String ? (String) response.getCredential() : objectMapper.writeValueAsString(response.getCredential());
        CredentialFormat format = Objects.requireNonNull(CredentialFormat.Companion.fromValue(response.getFormat()));
        CredentialVerificationSummary summary = credentialsVerifier.verifyAndGetCredentialStatus(
                credentialString, format,
                statusPurposeList != null && !statusPurposeList.isEmpty() ? statusPurposeList : defaultStatusPurposeList);
        VerificationResult result = summary.getVerificationResult();
        assertSignatureValid(result);
        return new CredentialVerificationResult(collectStatus(summary.getCredentialStatus()), isExpired(result));
    }

    private boolean isExpired(VerificationResult result) {
        String errorCode = result.getVerificationErrorCode();
        return errorCode != null && errorCode.toUpperCase().contains("EXPIRED");
    }

    private void assertSignatureValid(VerificationResult result) throws VCVerificationException {
        if (!result.getVerificationStatus()) {
            throw new VCVerificationException(result.getVerificationErrorCode().toLowerCase(), result.getVerificationMessage());
        }
    }

    /**
     * Persist the verifier map as-is. Empty map means no status pointer.
     * bits=1 VALID is only revocation. INVALID is only revocation. SUSPENDED is
     * only suspension. A failed GET/CWT puts error on the returned purposes.
     */
    private List<CredentialStatusCheck> collectStatus(Map<String, CredentialStatusResult> statuses) {
        if (statuses == null || statuses.isEmpty()) {
            log.info("Credential has no status list reference; skipping status check");
            return List.of();
        }
        List<CredentialStatusCheck> statusChecks = new ArrayList<>();
        for (Map.Entry<String, CredentialStatusResult> entry : statuses.entrySet()) {
            CredentialStatusResult result = entry.getValue();
            if (result != null && result.getError() != null) {
                String detail = result.getError().getErrorCode().name();
                log.error("Credential status check failed: {}", detail);
                throw new CredentialStatusException(CREDENTIAL_STATUS_UNAVAILABLE, detail);
            }
            statusChecks.add(new CredentialStatusCheck(entry.getKey(), result.isValid()));
        }
        return statusChecks;
    }
}
