package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.mimoto.dto.mimoto.CredentialVerificationResult;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.exception.VCVerificationException;

public interface CredentialVerifierService {

    /**
     * Verifies crypto and returns status-list checks plus expiry.
     * Status purposes come from {@code mosip.inji.credential.status.purpose-list}.
     */
    CredentialVerificationResult verify(VCCredentialResponse credentialResponse)
            throws JsonProcessingException, VCVerificationException;
}
