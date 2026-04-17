package io.mosip.mimoto.util.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.VCSpecificationVersion;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.dto.mimoto.wellknown.v1.CredentialMetaData;
import io.mosip.mimoto.dto.mimoto.wellknown.v1.V1WellKnownResponse;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.util.V1CredentialIssuerWellknownResponseValidator;
import jakarta.validation.Validator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Component
public class V1WellknownParser implements WellknownResponseParser {

    private final ObjectMapper objectMapper;
    private final V1CredentialIssuerWellknownResponseValidator wellknownResponseValidator;

    public V1WellknownParser(ObjectMapper objectMapper, V1CredentialIssuerWellknownResponseValidator wellknownResponseValidator) {
        this.objectMapper = objectMapper;
        this.wellknownResponseValidator = wellknownResponseValidator;
    }

    @Override
    public VCSpecificationVersion getSupportedVersion() {
        return VCSpecificationVersion.V1;
    }

    @Override
    public CredentialIssuerWellKnownResponse parse(String jsonResponse) throws IOException {
        V1WellKnownResponse v1Response = objectMapper.readValue(jsonResponse, V1WellKnownResponse.class);
        return toWellKnownResponse(v1Response);
    }

    @Override
    public void validate(CredentialIssuerWellKnownResponse response, Validator validator) throws InvalidWellknownResponseException {
        wellknownResponseValidator.validate(response, validator);
    }

    private CredentialIssuerWellKnownResponse toWellKnownResponse(V1WellKnownResponse v1Response) {
        CredentialIssuerWellKnownResponse wellKnownResponse = new CredentialIssuerWellKnownResponse();
        wellKnownResponse.setCredentialIssuer(v1Response.getCredentialIssuer());
        wellKnownResponse.setAuthorizationServers(v1Response.getAuthorizationServers());
        wellKnownResponse.setCredentialEndPoint(v1Response.getCredentialEndPoint());
        wellKnownResponse.setCredentialConfigurationsSupported(toCredentialConfigurations(v1Response));
        wellKnownResponse.setNonceEndpoint(v1Response.getNonceEndpoint());
        wellKnownResponse.setVersion(getSupportedVersion());
        return wellKnownResponse;
    }

    private Map<String, CredentialsSupportedResponse> toCredentialConfigurations(V1WellKnownResponse v1Response) {
        LinkedHashMap<String, CredentialsSupportedResponse> resultMap = new LinkedHashMap<>();
        v1Response.getCredentialConfigurationsSupported().forEach((key, value) -> resultMap.put(key, toCredentialSupported(value)));
        return resultMap;
    }

    private CredentialsSupportedResponse toCredentialSupported(io.mosip.mimoto.dto.mimoto.wellknown.v1.CredentialsSupportedResponse v1CredentialSupportedResponse) {
        CredentialsSupportedResponse credentialSupported = new CredentialsSupportedResponse();
        credentialSupported.setFormat(v1CredentialSupportedResponse.getFormat());
        credentialSupported.setScope(v1CredentialSupportedResponse.getScope());
        credentialSupported.setDoctype(v1CredentialSupportedResponse.getDoctype());
        credentialSupported.setProofTypesSupported(objectMapper.convertValue(v1CredentialSupportedResponse.getProofTypesSupported(), objectMapper.getTypeFactory().constructMapType(LinkedHashMap.class, String.class, io.mosip.mimoto.dto.mimoto.ProofTypesSupported.class)));
        credentialSupported.setVct(v1CredentialSupportedResponse.getVct());
        
        CredentialMetaData metadata = v1CredentialSupportedResponse.getCredentialMetadata();
        if (metadata != null) {
            if (metadata.getDisplay() != null) {
                List<io.mosip.mimoto.dto.mimoto.CredentialSupportedDisplayResponse> display = metadata.getDisplay().stream().map(d -> objectMapper.convertValue(d, io.mosip.mimoto.dto.mimoto.CredentialSupportedDisplayResponse.class)).collect(Collectors.toList());
                credentialSupported.setDisplay(display);
            }
            credentialSupported.setClaims(normalizeClaims(metadata.getClaims()));
        }

        return credentialSupported;
    }

    private Map<String, Object> normalizeClaims(List<Map<String, Object>> claimsList) {
        if (claimsList == null || claimsList.isEmpty()) {
            return null;
        }
        LinkedHashMap<String, Object> claimsMap = new LinkedHashMap<>();
        for (Map<String, Object> claim : claimsList) {
            List<String> path = (List<String>) claim.get("path");
            if (path == null || path.isEmpty()) continue;
            String key = path.getLast();
            if (key == null) continue;
            claimsMap.put(key, Map.of("display", claim.getOrDefault("display", List.of())));
        }
        return claimsMap.isEmpty() ? null : claimsMap;
    }
}
