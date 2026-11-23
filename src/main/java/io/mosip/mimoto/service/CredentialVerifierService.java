package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.mimoto.dto.mimoto.CredentialVerificationResult;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.exception.VCVerificationException;

import java.util.List;

public interface CredentialVerifierService {

    List<String> STATUS_PURPOSE_LIST = List.of("revocation", "suspension");

    /**
     * Verifies crypto and returns status-list checks plus expiry.
     * {@code statusPurposeList} is optional; null or empty uses {@link #STATUS_PURPOSE_LIST}.
     */
    CredentialVerificationResult verify(VCCredentialResponse credentialResponse, List<String> statusPurposeList)
            throws JsonProcessingException, VCVerificationException;
}
