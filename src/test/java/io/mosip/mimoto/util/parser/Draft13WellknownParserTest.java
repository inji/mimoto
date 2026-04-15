package io.mosip.mimoto.util.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.VCSpecificationVersion;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.util.CredentialIssuerWellknownResponseValidator;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class Draft13WellknownParserTest {

    private Draft13WellknownParser parser;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        parser = new Draft13WellknownParser(objectMapper, new CredentialIssuerWellknownResponseValidator());
    }

    @Test
    void shouldReturnDraft13AsVersion() {
        assertEquals(VCSpecificationVersion.DRAFT_13, parser.getSupportedVersion());
    }

    @Test
    void shouldParseDraft13ResponseWithDisplayAndOrder() throws IOException {
        String json = """
                {
                    "credential_issuer": "https://issuer.example.com",
                    "authorization_servers": ["https://auth.example.com"],
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "credential_configurations_supported": {
                        "UniversityDegree": {
                            "format": "ldp_vc",
                            "scope": "university_degree",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                            },
                            "display": [
                                {"name": "University Degree", "locale": "en"}
                            ],
                            "order": ["name", "degree"],
                            "vct": "UniversityDegreeCredential"
                        }
                    }
                }
                """;

        CredentialIssuerWellKnownResponse result = parser.parse(json);

        assertEquals("https://issuer.example.com", result.getCredentialIssuer());
        assertEquals(List.of("https://auth.example.com"), result.getAuthorizationServers());
        assertEquals("https://issuer.example.com/credential", result.getCredentialEndPoint());
        assertNull(result.getNonceEndpoint());

        assertNotNull(result.getCredentialConfigurationsSupported());
        CredentialsSupportedResponse cred = result.getCredentialConfigurationsSupported().get("UniversityDegree");
        assertNotNull(cred);
        assertEquals("ldp_vc", cred.getFormat());
        assertEquals("university_degree", cred.getScope());
        assertEquals("UniversityDegreeCredential", cred.getVct());
        assertNotNull(cred.getDisplay());
        assertEquals(1, cred.getDisplay().size());
        assertEquals("University Degree", cred.getDisplay().get(0).getName());
        assertEquals(List.of("name", "degree"), cred.getOrder());
    }

    @Test
    void shouldMapAllFieldsFromDraft13Config() throws IOException {
        String json = """
                {
                    "credential_issuer": "https://issuer.example.com",
                    "authorization_servers": ["https://auth1.com", "https://auth2.com"],
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "credential_configurations_supported": {
                        "Cred1": {
                            "format": "ldp_vc",
                            "scope": "scope1",
                            "doctype": "doctype1",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]},
                                "cwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
                            },
                            "claims": {"field1": {}, "field2": {}},
                            "credential_definition": {
                                "type": ["VerifiableCredential"],
                                "credentialSubject": {"name": {"display": [{"name": "Name", "locale": "en"}]}}
                            },
                            "display": [
                                {"name": "Credential One", "locale": "en"},
                                {"name": "Credenziale Uno", "locale": "it"}
                            ],
                            "order": ["name", "dob"],
                            "vct": "VCT1"
                        }
                    }
                }
                """;

        CredentialIssuerWellKnownResponse result = parser.parse(json);

        assertEquals(2, result.getAuthorizationServers().size());
        CredentialsSupportedResponse cred = result.getCredentialConfigurationsSupported().get("Cred1");
        assertEquals("ldp_vc", cred.getFormat());
        assertEquals("scope1", cred.getScope());
        assertEquals("doctype1", cred.getDoctype());
        assertEquals(2, cred.getProofTypesSupported().size());
        assertEquals(2, cred.getClaims().size());
        assertNotNull(cred.getCredentialDefinition());
        assertEquals(List.of("VerifiableCredential"), cred.getCredentialDefinition().getType());
        assertEquals(2, cred.getDisplay().size());
        assertEquals(List.of("name", "dob"), cred.getOrder());
        assertEquals("VCT1", cred.getVct());
    }

    @Test
    void shouldParseMultipleCredentialConfigurations() throws IOException {
        String json = """
                {
                    "credential_issuer": "https://issuer.example.com",
                    "authorization_servers": ["https://auth.example.com"],
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "credential_configurations_supported": {
                        "Cred1": {
                            "format": "ldp_vc",
                            "scope": "scope1",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                            },
                            "display": [{"name": "Cred1", "locale": "en"}]
                        },
                        "Cred2": {
                            "format": "mso_mdoc",
                            "scope": "scope2",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                            },
                            "display": [{"name": "Cred2", "locale": "en"}]
                        }
                    }
                }
                """;

        CredentialIssuerWellKnownResponse result = parser.parse(json);

        assertEquals(2, result.getCredentialConfigurationsSupported().size());
        assertEquals("ldp_vc", result.getCredentialConfigurationsSupported().get("Cred1").getFormat());
        assertEquals("mso_mdoc", result.getCredentialConfigurationsSupported().get("Cred2").getFormat());
    }

    @Test
    void shouldNotSetNonceEndpointForDraft13() throws IOException {
        String json = """
                {
                    "credential_issuer": "https://issuer.example.com",
                    "authorization_servers": ["https://auth.example.com"],
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "credential_configurations_supported": {}
                }
                """;

        CredentialIssuerWellKnownResponse result = parser.parse(json);

        assertNull(result.getNonceEndpoint());
    }

    @Test
    void shouldThrowIOExceptionForInvalidJson() {
        assertThrows(IOException.class, () -> parser.parse("not valid json"));
    }

    @Test
    void shouldDelegateValidationToValidator() {
        CredentialIssuerWellKnownResponse response = new CredentialIssuerWellKnownResponse();
        response.setCredentialConfigurationsSupported(Map.of());

        Validator noOpValidator = new NoOpValidator();

        assertDoesNotThrow(() -> parser.validate(response, noOpValidator));
    }

    @Test
    void shouldPropagateValidationException() {
        Draft13WellknownParser throwingParser = new Draft13WellknownParser(objectMapper, new ThrowingValidator());

        CredentialIssuerWellKnownResponse response = new CredentialIssuerWellKnownResponse();
        Validator noOpValidator = new NoOpValidator();

        assertThrows(InvalidWellknownResponseException.class,
                () -> throwingParser.validate(response, noOpValidator));
    }

    @Test
    void shouldHandleNullOptionalFields() throws IOException {
        String json = """
                {
                    "credential_issuer": "https://issuer.example.com",
                    "authorization_servers": ["https://auth.example.com"],
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "credential_configurations_supported": {
                        "Cred1": {
                            "format": "ldp_vc",
                            "scope": "scope1",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                            },
                            "display": [{"name": "Test", "locale": "en"}]
                        }
                    }
                }
                """;

        CredentialIssuerWellKnownResponse result = parser.parse(json);

        CredentialsSupportedResponse cred = result.getCredentialConfigurationsSupported().get("Cred1");
        assertNull(cred.getDoctype());
        assertNull(cred.getClaims());
        assertNull(cred.getCredentialDefinition());
        assertNull(cred.getOrder());
    }

    private static class ThrowingValidator extends CredentialIssuerWellknownResponseValidator {
        @Override
        public void validate(CredentialIssuerWellKnownResponse response, Validator validator) throws InvalidWellknownResponseException {
            throw new InvalidWellknownResponseException("test error");
        }
    }

    @SuppressWarnings("unchecked")
    private static class NoOpValidator implements Validator {
        @Override
        public <T> Set<ConstraintViolation<T>> validate(T object, Class<?>... groups) {
            return new HashSet<>();
        }

        @Override
        public <T> Set<ConstraintViolation<T>> validateProperty(T object, String propertyName, Class<?>... groups) {
            return new HashSet<>();
        }

        @Override
        public <T> Set<ConstraintViolation<T>> validateValue(Class<T> beanType, String propertyName, Object value, Class<?>... groups) {
            return new HashSet<>();
        }

        @Override
        public jakarta.validation.metadata.BeanDescriptor getConstraintsForClass(Class<?> clazz) {
            return null;
        }

        @Override
        public <T> T unwrap(Class<T> type) {
            return null;
        }

        @Override
        public jakarta.validation.executable.ExecutableValidator forExecutables() {
            return null;
        }
    }
}
