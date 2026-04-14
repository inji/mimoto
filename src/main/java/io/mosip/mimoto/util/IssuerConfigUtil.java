package io.mosip.mimoto.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.VCSpecificationVersion;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.util.parser.WellknownParserFactory;
import io.mosip.mimoto.util.parser.WellknownResponseParser;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import java.io.IOException;
import java.util.Set;


@Service
@Slf4j
public class IssuerConfigUtil {

    @Autowired
    private RestApiClient restApiClient;

    @Autowired
    private VCSpecVersionDetector versionDetector;

    @Autowired
    private WellknownParserFactory parserFactory;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    private Validator validator;

    public static String camelToTitleCase(String input) {
        if (input == null || input.isEmpty()) return input;

        // Insert space before:
        // 1. Lowercase followed by uppercase (e.g., pinFor -> pin For)
        // 2. Acronym followed by normal word (e.g., PRACondition -> PRA Condition)
        String result = input.replaceAll("(?<=[a-z])(?=[A-Z])|(?<=[A-Z]{2,})(?=[A-Z][a-z])", " ");

        // Capitalize first letter of each word, preserve acronyms
        String[] words = result.split(" ");
        StringBuilder finalResult = new StringBuilder();

        for (String word : words) {
            if (word.matches("[A-Z]{2,}")) {
                // Acronym (all uppercase, length >= 2)
                finalResult.append(word);
            } else {
                // Capitalize normally
                finalResult.append(Character.toUpperCase(word.charAt(0)))
                        .append(word.substring(1));
            }
            finalResult.append(" ");
        }

        return finalResult.toString().trim();
    }

//    @Cacheable(value = "issuerWellknown", key = "#p0")
    public CredentialIssuerWellKnownResponse getIssuerWellknown(String credentialIssuerHost) throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        String wellknownEndpoint = credentialIssuerHost + "/.well-known/openid-credential-issuer";
        String wellknownResponse = restApiClient.getApi(wellknownEndpoint, String.class);
        if (wellknownResponse == null) {
            throw new ApiNotAccessibleException();
        }

        JsonNode jsonNode = objectMapper.readTree(wellknownResponse);
        VCSpecificationVersion version = versionDetector.detectVersion(jsonNode);

        WellknownResponseParser parser = parserFactory.getParser(version);
        CredentialIssuerWellKnownResponse parsedResponse = parser.parse(wellknownResponse);
        parser.validate(parsedResponse, validator);

        return parsedResponse;
    }

    @Cacheable(value = "authServerWellknown", key = "#p0")
    public AuthorizationServerWellKnownResponse getAuthServerWellknown(String authorizationServerHostUrl) throws AuthorizationServerWellknownResponseException {
        try {
            String wellknownEndpoint = authorizationServerHostUrl + "/.well-known/oauth-authorization-server";
            log.debug("fetching Authorization Server Wellknown by calling :: " + wellknownEndpoint);
            String wellknownResponse = restApiClient.getApi(wellknownEndpoint, String.class);
            if (wellknownResponse == null) {
                throw new Exception("well-known api is not accessible");
            }
            AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse = objectMapper.readValue(wellknownResponse, AuthorizationServerWellKnownResponse.class);
            validate(authorizationServerWellKnownResponse);

            return authorizationServerWellKnownResponse;
        } catch (Exception e) {
            log.error("Exception occurred while fetching Authorization Server wellknown ", e);
            throw new AuthorizationServerWellknownResponseException(e.toString());
        }
    }

    public void validate(AuthorizationServerWellKnownResponse response) throws Exception {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        Validator validator = factory.getValidator();
        Set<ConstraintViolation<AuthorizationServerWellKnownResponse>> violations = validator.validate(response);
        if (!violations.isEmpty()) {
            StringBuilder sb = new StringBuilder("Validation failed:");
            for (ConstraintViolation<AuthorizationServerWellKnownResponse> violation : violations) {
                sb.append("\n").append(violation.getPropertyPath()).append(": ").append(violation.getMessage());
            }

            throw new Exception(sb.toString());
        }
    }
}
