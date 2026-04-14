package io.mosip.mimoto.util.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.VCSpecificationVersion;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.dto.mimoto.wellknown.v1.CredentialMetaData;
import io.mosip.mimoto.dto.mimoto.wellknown.v1.V1WellKnownResponse;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.util.CredentialIssuerWellknownResponseValidator;
import jakarta.validation.Validator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component("v1WellknownParser")
public class V1WellknownParser implements WellknownResponseParser {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CredentialIssuerWellknownResponseValidator wellknownResponseValidator;

    @Override
    public VCSpecificationVersion getSupportedVersion() {
        return VCSpecificationVersion.V1;
    }

    @Override
    public CredentialIssuerWellKnownResponse parse(String jsonResponse) throws IOException {
        V1WellKnownResponse v1Response = objectMapper.readValue(jsonResponse, V1WellKnownResponse.class);
        return mapToUnifiedResponse(v1Response);
    }

    @Override
    public void validate(CredentialIssuerWellKnownResponse response, Validator validator) throws InvalidWellknownResponseException {
        wellknownResponseValidator.validate(response, validator);
    }

    private CredentialIssuerWellKnownResponse mapToUnifiedResponse(V1WellKnownResponse v1Response) {
        CredentialIssuerWellKnownResponse response = new CredentialIssuerWellKnownResponse();
        response.setCredentialIssuer(v1Response.getCredentialIssuer());
        response.setAuthorizationServers(v1Response.getAuthorizationServers());
        response.setCredentialEndPoint(v1Response.getCredentialEndPoint());
        response.setCredentialConfigurationsSupported(convertCredentialConfigurations(v1Response));
        response.setNonceEndpoint(v1Response.getNonceEndpoint());
        return response;
    }

    private Map<String, CredentialsSupportedResponse> convertCredentialConfigurations(V1WellKnownResponse v1Response) {
        if (v1Response.getCredentialConfigurationsSupported() == null) {
            return new LinkedHashMap<>();
        }
        return v1Response.getCredentialConfigurationsSupported().entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> mapToUnifiedCredentialSupported(entry.getValue()), (existing, replacement) -> existing, LinkedHashMap::new));
    }

    private CredentialsSupportedResponse mapToUnifiedCredentialSupported(io.mosip.mimoto.dto.mimoto.wellknown.v1.CredentialsSupportedResponse v1Config) {
        CredentialsSupportedResponse unified = new CredentialsSupportedResponse();
        unified.setFormat(v1Config.getFormat());
        unified.setScope(v1Config.getScope());
        unified.setDoctype(v1Config.getDoctype());
        unified.setProofTypesSupported(v1Config.getProofTypesSupported());
        unified.setClaims(v1Config.getClaims());
        unified.setCredentialDefinition(v1Config.getCredentialDefinition());
        unified.setVct(v1Config.getVct());

        CredentialMetaData metadata = v1Config.getCredentialMetadata();
        if (metadata != null) {
            unified.setDisplay(metadata.getDisplay());
        }

        return unified;
    }
}
