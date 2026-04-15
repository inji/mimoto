package io.mosip.mimoto.util.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.VCSpecificationVersion;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.wellknown.draft13.Draft13WellKnownResponse;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.util.CredentialIssuerWellknownResponseValidator;
import jakarta.validation.Validator;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.LinkedHashMap;

@Component
public class Draft13WellknownParser implements WellknownResponseParser {

    private final ObjectMapper objectMapper;
    private final CredentialIssuerWellknownResponseValidator wellknownResponseValidator;

    public Draft13WellknownParser(ObjectMapper objectMapper, CredentialIssuerWellknownResponseValidator wellknownResponseValidator) {
        this.objectMapper = objectMapper;
        this.wellknownResponseValidator = wellknownResponseValidator;
    }

    @Override
    public VCSpecificationVersion getSupportedVersion() {
        return VCSpecificationVersion.DRAFT_13;
    }

    @Override
    public CredentialIssuerWellKnownResponse parse(String jsonResponse) throws IOException {
        Draft13WellKnownResponse draft13Response = objectMapper.readValue(jsonResponse, Draft13WellKnownResponse.class);
        return objectMapper.convertValue(draft13Response, CredentialIssuerWellKnownResponse.class);
    }

    @Override
    public void validate(CredentialIssuerWellKnownResponse response, Validator validator) throws InvalidWellknownResponseException {
        wellknownResponseValidator.validate(response, validator);
    }
}
