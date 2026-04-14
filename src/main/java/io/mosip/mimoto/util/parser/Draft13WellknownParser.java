package io.mosip.mimoto.util.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.VCSpecificationVersion;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.dto.mimoto.wellknown.draft13.Draft13WellKnownResponse;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.util.CredentialIssuerWellknownResponseValidator;
import jakarta.validation.Validator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component("draft13WellknownParser")
public class Draft13WellknownParser implements WellknownResponseParser {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CredentialIssuerWellknownResponseValidator wellknownResponseValidator;

    @Override
    public VCSpecificationVersion getSupportedVersion() {
        return VCSpecificationVersion.DRAFT_13;
    }

    @Override
    public CredentialIssuerWellKnownResponse parse(String jsonResponse) throws IOException {
        Draft13WellKnownResponse draft13Response = objectMapper.readValue(jsonResponse, Draft13WellKnownResponse.class);
        return mapToUnifiedResponse(draft13Response);
    }

    @Override
    public void validate(CredentialIssuerWellKnownResponse response, Validator validator) throws InvalidWellknownResponseException {
        wellknownResponseValidator.validate(response, validator);
    }

    private CredentialIssuerWellKnownResponse mapToUnifiedResponse(Draft13WellKnownResponse draft13Response) {
        CredentialIssuerWellKnownResponse response = new CredentialIssuerWellKnownResponse();
        response.setCredentialIssuer(draft13Response.getCredentialIssuer());
        response.setAuthorizationServers(draft13Response.getAuthorizationServers());
        response.setCredentialEndPoint(draft13Response.getCredentialEndPoint());
        response.setCredentialConfigurationsSupported(convertCredentialConfigurations(draft13Response));
        return response;
    }

    private Map<String, CredentialsSupportedResponse> convertCredentialConfigurations(Draft13WellKnownResponse draft13Response) {
        if (draft13Response.getCredentialConfigurationsSupported() == null) {
            return new LinkedHashMap<>();
        }
        return draft13Response.getCredentialConfigurationsSupported().entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> mapToUnifiedCredentialSupported(entry.getValue()), (existing, replacement) -> existing, LinkedHashMap::new));
    }

    private CredentialsSupportedResponse mapToUnifiedCredentialSupported(io.mosip.mimoto.dto.mimoto.wellknown.draft13.CredentialsSupportedResponse draft13Config) {
        CredentialsSupportedResponse unified = new CredentialsSupportedResponse();
        unified.setFormat(draft13Config.getFormat());
        unified.setScope(draft13Config.getScope());
        unified.setDoctype(draft13Config.getDoctype());
        unified.setProofTypesSupported(draft13Config.getProofTypesSupported());
        unified.setClaims(draft13Config.getClaims());
        unified.setCredentialDefinition(draft13Config.getCredentialDefinition());
        unified.setDisplay(draft13Config.getDisplay());
        unified.setOrder(draft13Config.getOrder());
        unified.setVct(draft13Config.getVct());
        return unified;
    }
}
