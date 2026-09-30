package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static io.mosip.mimoto.util.TestUtilities.getCredentialIssuerWellKnownResponseDto;
import static io.mosip.mimoto.util.TestUtilities.getCredentialSupportedResponse;
import static org.junit.jupiter.api.Assertions.*;

class V1CredentialIssuerWellknownResponseValidatorTest {

    private Validator validator;
    private final V1CredentialIssuerWellknownResponseValidator v1Validator = new V1CredentialIssuerWellknownResponseValidator();

    @BeforeEach
    void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Test
    void shouldPassValidationForV1LdpVcWithDisplayAndClaims() {
        CredentialsSupportedResponse config = getCredentialSupportedResponse("CredentialType1");
        config.setCredentialDefinition(null);
        config.setClaims(Map.of("given_name", Map.of("display", java.util.List.of(Map.of("name", "Given Name", "locale", "en")))));

        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", config));

        assertDoesNotThrow(() -> v1Validator.validate(response, validator));
    }

    @Test
    void shouldFailValidationForV1LdpVcWithoutDisplay() {
        CredentialsSupportedResponse config = getCredentialSupportedResponse("CredentialType1");
        config.setCredentialDefinition(null);
        config.setDisplay(null);
        config.setClaims(Map.of("given_name", Map.of()));

        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", config));

        InvalidWellknownResponseException exception = assertThrows(InvalidWellknownResponseException.class,
                () -> v1Validator.validate(response, validator));
        assertTrue(exception.getMessage().contains("All credential configurations in issuer well-known are invalid"));
    }

    @Test
    void shouldFailValidationForV1LdpVcWithEmptyDisplay() {
        CredentialsSupportedResponse config = getCredentialSupportedResponse("CredentialType1");
        config.setCredentialDefinition(null);
        config.setDisplay(Collections.emptyList());
        config.setClaims(Map.of("given_name", Map.of()));

        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", config));

        InvalidWellknownResponseException exception = assertThrows(InvalidWellknownResponseException.class,
                () -> v1Validator.validate(response, validator));
        assertTrue(exception.getMessage().contains("All credential configurations in issuer well-known are invalid"));
    }

    @Test
    void shouldFailValidationForV1LdpVcWithoutClaims() {
        CredentialsSupportedResponse config = getCredentialSupportedResponse("CredentialType1");
        config.setCredentialDefinition(null);
        config.setClaims(null);

        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", config));

        InvalidWellknownResponseException exception = assertThrows(InvalidWellknownResponseException.class,
                () -> v1Validator.validate(response, validator));
        assertTrue(exception.getMessage().contains("All credential configurations in issuer well-known are invalid"));
    }

    @Test
    void shouldSkipInvalidConfigAndRetainValidConfigWhenMixedConfigurationsProvided() {
        CredentialsSupportedResponse validConfig = getCredentialSupportedResponse("validConfig");
        validConfig.setCredentialDefinition(null);
        validConfig.setClaims(Map.of("given_name", Map.of("display", java.util.List.of(Map.of("name", "Given Name", "locale", "en")))));

        CredentialsSupportedResponse invalidConfig = getCredentialSupportedResponse("invalidConfig");
        invalidConfig.setCredentialDefinition(null);
        invalidConfig.setClaims(null);

        Map<String, CredentialsSupportedResponse> configs = new LinkedHashMap<>();
        configs.put("validConfig", validConfig);
        configs.put("invalidConfig", invalidConfig);

        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1", configs);

        assertDoesNotThrow(() -> v1Validator.validate(response, validator));
        assertEquals(Set.of("validConfig"), response.getCredentialConfigurationsSupported().keySet());
    }

    @Test
    void shouldFailValidationForV1LdpVcWithEmptyClaims() {
        CredentialsSupportedResponse config = getCredentialSupportedResponse("CredentialType1");
        config.setCredentialDefinition(null);
        config.setClaims(Map.of());

        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", config));

        InvalidWellknownResponseException exception = assertThrows(InvalidWellknownResponseException.class,
                () -> v1Validator.validate(response, validator));
        assertTrue(exception.getMessage().contains("All credential configurations in issuer well-known are invalid"));
    }
}
