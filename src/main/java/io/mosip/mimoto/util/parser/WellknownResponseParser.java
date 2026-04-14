package io.mosip.mimoto.util.parser;

import io.mosip.mimoto.constant.VCSpecificationVersion;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import jakarta.validation.Validator;

import java.io.IOException;

public interface WellknownResponseParser {

    VCSpecificationVersion getSupportedVersion();

    CredentialIssuerWellKnownResponse parse(String jsonResponse) throws IOException;

    void validate(CredentialIssuerWellKnownResponse response, Validator validator)
            throws InvalidWellknownResponseException;
}
