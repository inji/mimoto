package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.mimoto.CredentialDefinitionResponseDto;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialSupportedDisplayResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.*;

import static io.mosip.mimoto.util.TestUtilities.getCredentialIssuerWellKnownResponseDto;
import static io.mosip.mimoto.util.TestUtilities.getCredentialSupportedResponse;
import static org.junit.jupiter.api.Assertions.*;

import org.springframework.boot.autoconfigure.validation.ValidationAutoConfiguration;

@SpringBootTest(classes = {CredentialIssuerWellknownResponseValidator.class, CredentialIssuerWellKnownResponse.class, ValidationAutoConfiguration.class})
class CredentialIssuerWellknownResponseValidatorTest {

    @Autowired
    private Validator validator;

    @Autowired
    private CredentialIssuerWellKnownResponse response;

    @BeforeEach
    void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
        response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
    }

    @Test
    void shouldNotThrowExceptionWhenResponseIsFullyValid() {
        CredentialIssuerWellknownResponseValidator validatorInstance = new CredentialIssuerWellknownResponseValidator();

        assertDoesNotThrow(() -> validatorInstance.validate(response, validator));
    }

    @Test
    void shouldThrowExceptionWhenFormatIsMissingInCredentialsSupported() {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        credentialsSupportedResponse.setFormat(null);
        response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", credentialsSupportedResponse));

        CredentialIssuerWellknownResponseValidator validatorInstance = new CredentialIssuerWellknownResponseValidator();

        InvalidWellknownResponseException exception = assertThrows(InvalidWellknownResponseException.class, () ->
                validatorInstance.validate(response, validator));
        assertEquals("RESIDENT-APP-041", exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Validation failed:"));
        assertTrue(exception.getMessage().contains("Format must not be blank"));
    }

    @Test
    void shouldIncludeAllViolationsInExceptionMessageWhenMultipleFieldsAreInvalid() {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        credentialsSupportedResponse.setFormat(null);
        credentialsSupportedResponse.setScope(null);
        credentialsSupportedResponse.setDisplay(null);
        credentialsSupportedResponse.setProofTypesSupported(null);
        response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", credentialsSupportedResponse));

        CredentialIssuerWellknownResponseValidator validatorInstance = new CredentialIssuerWellknownResponseValidator();

        InvalidWellknownResponseException exception = assertThrows(InvalidWellknownResponseException.class, () ->
                validatorInstance.validate(response, validator));
        String message = exception.getMessage();
        assertTrue(message.contains("Validation failed:"));
        assertTrue(message.contains("Format must not be blank"));
        assertTrue(message.contains("Scope must not be blank"));
        assertTrue(message.contains("Display information must not be empty"));
        assertTrue(message.contains("Proof types supported must not be empty"));
    }

    @Test
    void shouldThrowExceptionWhenDisplayHasInvalidNestedFields() {
        List<CredentialSupportedDisplayResponse> displayList = new ArrayList<>();
        CredentialSupportedDisplayResponse invalidDisplay = new CredentialSupportedDisplayResponse();
        invalidDisplay.setName(null);
        invalidDisplay.setLocale(null);
        invalidDisplay.setLogo(null);
        invalidDisplay.setTextColor(null);
        invalidDisplay.setBackgroundColor(null);
        displayList.add(invalidDisplay);
        response.getCredentialConfigurationsSupported().get("CredentialType1").setDisplay(displayList);

        CredentialIssuerWellknownResponseValidator validatorInstance = new CredentialIssuerWellknownResponseValidator();

        InvalidWellknownResponseException exception = assertThrows(InvalidWellknownResponseException.class, () ->
                validatorInstance.validate(response, validator));
        String message = exception.getMessage();
        assertTrue(message.contains("Validation failed:"));
        assertTrue(message.contains("name: must not be blank"));
        assertTrue(message.contains("locale: must not be blank"));
        assertTrue(message.contains("logo: must not be null"));
    }

    @Nested
    class LdpVcFormatWellKnownResponseValidationTest {
        @Test
        void shouldDetectMissingMandatoryFieldsCredentialDefinitionOfCredentialSupportedResponse() {
            response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                    Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
            response.getCredentialConfigurationsSupported().get("CredentialType1").setCredentialDefinition(null);
            CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();

            InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                    credentialIssuerWellknownResponseValidator.validate(response, validator));
            assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
            assertEquals("""
                    RESIDENT-APP-041 --> Invalid Wellknown from Issuer
                    credentialDefinition: must not be null""", invalidWellknownResponseException.getMessage());
        }

        @Test
        void shouldDetectMissingMandatoryFieldsOfCredentialDefinitionInWellknownResponse() {
            response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                    Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
            CredentialDefinitionResponseDto credentialDefinitionResponseDto = new CredentialDefinitionResponseDto();
            credentialDefinitionResponseDto.setCredentialSubject(null);
            credentialDefinitionResponseDto.setType(null);
            response.getCredentialConfigurationsSupported().get("CredentialType1").setCredentialDefinition(credentialDefinitionResponseDto);

            CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
            InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                    credentialIssuerWellknownResponseValidator.validate(response, validator)
            );

            // Update to check message contains validation errors
            String message = invalidWellknownResponseException.getMessage();
            assertTrue(message.contains("RESIDENT-APP-041 --> Invalid Wellknown from Issuer"));
            assertTrue(message.contains("type: must not be empty"));
        }

        @Test
        void shouldThrowExceptionWhenCredentialDefinitionTypeIsEmpty() {
            response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                    Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
            response.getCredentialConfigurationsSupported().get("CredentialType1").getCredentialDefinition().setType(Collections.emptyList());  // Invalid empty list

            CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();

            InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                    credentialIssuerWellknownResponseValidator.validate(response, validator));
            assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
            assertEquals("""
                    RESIDENT-APP-041 --> Invalid Wellknown from Issuer
                    Validation failed:
                    type: must not be empty""", invalidWellknownResponseException.getMessage());
        }
    }

    @Nested
    class MsoMdocFormatWellKnownResponseValidationTest {

        @Test
        void shouldThrowInvalidWellKnownResponseExceptionWhenMandatoryFieldDocTypeIsNotPresent() {
            CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
            CredentialsSupportedResponse credentialSupportedResponse1 = getCredentialSupportedResponse("CredentialType1", "mso_mdoc");
            credentialSupportedResponse1.setDoctype("");
            CredentialIssuerWellKnownResponse wellKnownResponseWithoutDocType = getCredentialIssuerWellKnownResponseDto("Issuer1",
                    Map.of("CredentialType1", credentialSupportedResponse1));

            InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                    credentialIssuerWellknownResponseValidator.validate(wellKnownResponseWithoutDocType, validator)
            );

            assertEquals("""
                    RESIDENT-APP-041 --> Invalid Wellknown from Issuer
                    Mandatory field 'doctype' missing""", invalidWellknownResponseException.getMessage());
        }

        @Test
        void shouldThrowInvalidWellKnownResponseExceptionWhenMandatoryFieldClaimIsNotPresent() {
            CredentialsSupportedResponse credentialSupportedResponse = getCredentialSupportedResponse("CredentialType1", "mso_mdoc");
            credentialSupportedResponse.setClaims(Map.of());
            CredentialIssuerWellKnownResponse wellKnownResponseWithoutClaims = getCredentialIssuerWellKnownResponseDto("Issuer1",
                    Map.of("CredentialType1", credentialSupportedResponse));

            CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
            InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                    credentialIssuerWellknownResponseValidator.validate(wellKnownResponseWithoutClaims, validator)
            );

            assertEquals("""
                    RESIDENT-APP-041 --> Invalid Wellknown from Issuer
                    Mandatory field 'claims' missing""", invalidWellknownResponseException.getMessage());
        }


        @Test
        void shouldNotThrowInvalidWellKnownResponseExceptionWhenMandatoryFieldsAreNotPresentInMsoMdocVc() {
            CredentialIssuerWellKnownResponse wellKnownResponseWithoutClaims = getCredentialIssuerWellKnownResponseDto("Issuer1",
                    Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1", "mso_mdoc")));

            CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();

            assertDoesNotThrow(() ->
                    credentialIssuerWellknownResponseValidator.validate(wellKnownResponseWithoutClaims, validator));

        }
    }
}
