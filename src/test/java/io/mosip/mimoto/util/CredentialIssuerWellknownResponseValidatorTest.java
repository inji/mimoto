package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.BackgroundImageDTO;
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
    void shouldThrowExceptionWhenCredentialIssuerIsMissingInCredentialIssuerWellknownResponse() {
        response.setCredentialIssuer("");
        response.setCredentialEndPoint("http://example.com/credential");

        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        assertEquals("""
                RESIDENT-APP-041 --> Invalid Wellknown from Issuer
                Validation failed:
                credentialIssuer: must not be blank""", invalidWellknownResponseException.getMessage());
    }

    @Test
    void shouldThrowExceptionWhenCredentialEndpointIsIncorrectInCredentialIssuerWellknownResponse() {
        response.setCredentialEndPoint("http://example.com"); // Incorrect because it does not end with "/credential"

        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        assertEquals("""
                RESIDENT-APP-041 --> Invalid Wellknown from Issuer
                Validation failed:
                credentialEndPoint: must match "https?://.*?/credential$\"""", invalidWellknownResponseException.getMessage(), "Exception message should indicate the incorrect 'credentialEndpoint'");
    }

    @Test
    void shouldThrowExceptionWhenAuthorizationServersIsEmpty() {
        response.setCredentialIssuer("https://valid.url/credential");
        response.setAuthorizationServers(Collections.emptyList());  // Invalid empty list

        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        assertEquals("""
                RESIDENT-APP-041 --> Invalid Wellknown from Issuer
                Validation failed:
                authorizationServers: must not be empty""", invalidWellknownResponseException.getMessage(), "Exception message should indicate 'authorizationServers' cannot be empty");
    }

    @Test
    void shouldThrowExceptionWhenAuthorizationServersIsNull() {
        response.setCredentialIssuer("https://valid.url/credential");
        response.setAuthorizationServers(null);

        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        assertEquals("""
                RESIDENT-APP-041 --> Invalid Wellknown from Issuer
                Validation failed:
                authorizationServers: must not be empty""", invalidWellknownResponseException.getMessage(), "Exception message should indicate 'authorizationServers' cannot be empty");
    }

    @Test
    void shouldThrowExceptionWhenFormatIsMissingInCredentialsSupported() {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        credentialsSupportedResponse.setFormat(null);
        response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", credentialsSupportedResponse));


        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        assertEquals("""
                RESIDENT-APP-041 --> Invalid Wellknown from Issuer
                Validation failed:
                credentialConfigurationsSupported[CredentialType1].format: Format must not be blank""", invalidWellknownResponseException.getMessage(), "Exception message should indicate 'format' must not be blank");
    }

    @Test
    void shouldThrowExceptionWhenLogoUrlIsInvalid() {
        response.getCredentialConfigurationsSupported().get("CredentialType1").getDisplay().getFirst().getLogo().setUrl("ftp//invalid-url");  // Invalid URL
        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();

        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        assertEquals("""
                RESIDENT-APP-041 --> Invalid Wellknown from Issuer
                Validation failed:
                credentialConfigurationsSupported[CredentialType1].display[0].logo.url: must be a valid URL""", invalidWellknownResponseException.getMessage(), "Exception message should indicate 'logo.url' must be a valid URL");
    }

    @Test
    void shouldThrowExceptionWhenBackgroundImageUrlIsInvalid() {
        response.getCredentialConfigurationsSupported().get("CredentialType1").getDisplay().getFirst().setBackgroundImage(new BackgroundImageDTO("local//imgbasebase64"));

        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();

        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        assertEquals("""
                RESIDENT-APP-041 --> Invalid Wellknown from Issuer
                Validation failed:
                credentialConfigurationsSupported[CredentialType1].display[0].backgroundImage.uri: must be a valid URL""", invalidWellknownResponseException.getMessage(), "Exception message should indicate 'background_image.uri' must be a valid URL");
    }

    @Test
    void shouldDetectMissingMandatoryFields() {
        response.setCredentialEndPoint(null);
        response.setCredentialConfigurationsSupported(null);
        response.setAuthorizationServers(null);
        response.setCredentialIssuer(null);
        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();

        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        assertTrue(Arrays.stream(invalidWellknownResponseException.getMessage().split("\n")).toList().containsAll(List.of("RESIDENT-APP-041 --> Invalid Wellknown from Issuer",
                "Validation failed:",
                "credentialIssuer: must not be blank",
                "credentialConfigurationsSupported: must not be empty",
                "authorizationServers: must not be empty",
                "credentialEndPoint: must not be blank")));
    }

    @Test
    void shouldDetectMissingMandatoryFieldsOfCredentialSupportedResponse() {
        response.getCredentialConfigurationsSupported().get("CredentialType1").setFormat(null);
        response.getCredentialConfigurationsSupported().get("CredentialType1").setScope(null);
        response.getCredentialConfigurationsSupported().get("CredentialType1").setDisplay(null);
        response.getCredentialConfigurationsSupported().get("CredentialType1").setProofTypesSupported(null);
        response.getCredentialConfigurationsSupported().get("CredentialType1").setCredentialDefinition(null);
        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();

        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        assertTrue(Arrays.stream(invalidWellknownResponseException.getMessage().split("\n")).toList().containsAll(Arrays.stream("""
                RESIDENT-APP-041 --> Invalid Wellknown from Issuer
                Validation failed:
                credentialConfigurationsSupported[CredentialType1].proofTypesSupported: Proof types supported must not be empty
                credentialConfigurationsSupported[CredentialType1].scope: Scope must not be blank
                credentialConfigurationsSupported[CredentialType1].format: Format must not be blank
                credentialConfigurationsSupported[CredentialType1].display: Display information must not be empty""".split("\n")).toList()));
    }

    @Test
    void shouldThrowExceptionIfProofTypesSupportedValueIsEmptyInCredentialSupportedResponse() {
        response.getCredentialConfigurationsSupported().get("CredentialType1").setProofTypesSupported(new HashMap<>());
        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();

        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        String message = invalidWellknownResponseException.getMessage();
        assertTrue(message.contains("RESIDENT-APP-041 --> Invalid Wellknown from Issuer"));
        assertTrue(message.contains("credentialConfigurationsSupported[CredentialType1].proofTypesSupported: Proof types supported must not be empty"));
    }

    @Test
    void shouldThrowExceptionIfProofSigningAlgorithmsSupportedValueIsNullInCredentialSupportedResponse() {
        response.getCredentialConfigurationsSupported().get("CredentialType1").getProofTypesSupported().get("jwt").setProofSigningAlgValuesSupported(null);
        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();

        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        String message = invalidWellknownResponseException.getMessage();
        assertTrue(message.contains("RESIDENT-APP-041 --> Invalid Wellknown from Issuer"));
        assertTrue(message.contains("credentialConfigurationsSupported[CredentialType1].proofTypesSupported[jwt].proofSigningAlgValuesSupported: must not be empty"));
    }

    @Test
    void shouldThrowExceptionIfProofSigningAlgorithmsSupportedValueIsEmptyInCredentialSupportedResponse() {
        response.getCredentialConfigurationsSupported().get("CredentialType1").getProofTypesSupported().get("jwt").setProofSigningAlgValuesSupported(new ArrayList<>());
        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();

        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        String message = invalidWellknownResponseException.getMessage();
        assertTrue(message.contains("RESIDENT-APP-041 --> Invalid Wellknown from Issuer"));
        assertTrue(message.contains("credentialConfigurationsSupported[CredentialType1].proofTypesSupported[jwt].proofSigningAlgValuesSupported: must not be empty"));
    }

    @Test
    void shouldDetectMissingMandatoryFieldsOfCredentialSupportedDisplayResponse() {
        // Create a new response object with nested display response details
        List<CredentialSupportedDisplayResponse> credentialSupportedDisplayResponseList = new ArrayList<>();
        CredentialSupportedDisplayResponse credentialSupportedDisplayResponse = new CredentialSupportedDisplayResponse();
        credentialSupportedDisplayResponse.setLogo(null);
        credentialSupportedDisplayResponse.setName(null);
        credentialSupportedDisplayResponse.setLocale(null);
        credentialSupportedDisplayResponse.setTextColor(null);
        credentialSupportedDisplayResponse.setBackgroundColor(null);
        credentialSupportedDisplayResponse.setBackgroundImage(null);
        credentialSupportedDisplayResponseList.add(credentialSupportedDisplayResponse);
        response.getCredentialConfigurationsSupported().get("CredentialType1").setDisplay(credentialSupportedDisplayResponseList);
        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();

        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator)
        );
        assertTrue(Arrays.stream(invalidWellknownResponseException.getMessage().split("\n")).toList().containsAll(Arrays.stream("""
                RESIDENT-APP-041 --> Invalid Wellknown from Issuer
                Validation failed:
                credentialConfigurationsSupported[CredentialType1].display[0].backgroundColor: must not be blank
                credentialConfigurationsSupported[CredentialType1].display[0].textColor: must not be blank
                credentialConfigurationsSupported[CredentialType1].display[0].name: must not be blank
                credentialConfigurationsSupported[CredentialType1].display[0].locale: must not be blank
                credentialConfigurationsSupported[CredentialType1].display[0].logo: must not be null""".split("\n")).toList()));
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
