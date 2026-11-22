package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.mimoto.dto.mimoto.CredentialVerificationResult;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.exception.VCVerificationException;

import java.util.List;

import static io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PURPOSE_REVOCATION;
import static io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PURPOSE_SUSPENSION;

public interface CredentialVerifierService {

    List<String> STATUS_PURPOSE_LIST = List.of(STATUS_PURPOSE_REVOCATION, STATUS_PURPOSE_SUSPENSION);

    /**
     * Verifies crypto and returns status-list checks plus expiry.
     * {@code statusPurposeList} is optional; null or empty uses {@link #STATUS_PURPOSE_LIST}.
     */
    CredentialVerificationResult verify(VCCredentialResponse credentialResponse, List<String> statusPurposeList)
            throws JsonProcessingException, VCVerificationException;
}
