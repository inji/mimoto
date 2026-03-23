package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.service.CredentialVerifierService;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
public class CredentialVerifierServiceImpl implements CredentialVerifierService {

    private final ObjectMapper objectMapper;

    private final CredentialsVerifier credentialsVerifier;

    public CredentialVerifierServiceImpl(ObjectMapper objectMapper, CredentialsVerifier credentialsVerifier) {
        this.objectMapper = objectMapper;
        this.credentialsVerifier = credentialsVerifier;
    }

    public boolean verify(VCCredentialResponse response) throws JsonProcessingException, VCVerificationException {
        String credentialString = response.getCredential() instanceof String ? (String) response.getCredential() : objectMapper.writeValueAsString(response.getCredential());
        VerificationResult result = credentialsVerifier.verify(credentialString, Objects.requireNonNull(CredentialFormat.Companion.fromValue(response.getFormat())));
        if (!result.getVerificationStatus()) {
            throw new VCVerificationException(result.getVerificationErrorCode().toLowerCase(), result.getVerificationMessage());
        }
        return true;
    }
}
