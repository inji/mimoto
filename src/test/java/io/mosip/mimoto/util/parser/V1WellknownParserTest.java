package io.mosip.mimoto.util.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.VCSpecificationVersion;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.util.V1CredentialIssuerWellknownResponseValidator;
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

class V1WellknownParserTest {

    private V1WellknownParser parser;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        parser = new V1WellknownParser(objectMapper, new V1CredentialIssuerWellknownResponseValidator());
    }

    @Test
    void shouldReturnV1AsVersion() {
        assertEquals(VCSpecificationVersion.V1, parser.getSupportedVersion());
    }

    @Test
    void shouldParseV1ResponseWithCredentialMetadata() throws IOException {
        String json = """
                {
                    "credential_issuer": "https://issuer.example.com",
                    "authorization_servers": ["https://auth.example.com"],
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "nonce_endpoint": "https://issuer.example.com/nonce",
                    "credential_configurations_supported": {
                        "UniversityDegree": {
                            "format": "ldp_vc",
                            "scope": "university_degree",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                            },
                            "credential_metadata": {
                                "display": [
                                    {"name": "University Degree", "locale": "en"}
                                ]
                            },
                            "vct": "UniversityDegreeCredential"
                        }
                    }
                }
                """;

        CredentialIssuerWellKnownResponse result = parser.parse(json);

        assertEquals("https://issuer.example.com", result.getCredentialIssuer());
        assertEquals(List.of("https://auth.example.com"), result.getAuthorizationServers());
        assertEquals("https://issuer.example.com/credential", result.getCredentialEndPoint());
        assertEquals("https://issuer.example.com/nonce", result.getNonceEndpoint());
        assertEquals(VCSpecificationVersion.V1, result.getVersion());

        assertNotNull(result.getCredentialConfigurationsSupported());
        CredentialsSupportedResponse cred = result.getCredentialConfigurationsSupported().get("UniversityDegree");
        assertNotNull(cred);
        assertEquals("ldp_vc", cred.getFormat());
        assertEquals("university_degree", cred.getScope());
        assertEquals("UniversityDegreeCredential", cred.getVct());
        assertNotNull(cred.getDisplay());
        assertEquals(1, cred.getDisplay().size());
        assertEquals("University Degree", cred.getDisplay().get(0).getName());
    }

    @Test
    void shouldParseV1ResponseWithNullCredentialMetadata() throws IOException {
        String json = """
                {
                    "credential_issuer": "https://issuer.example.com",
                    "authorization_servers": ["https://auth.example.com"],
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "credential_configurations_supported": {
                        "TestCred": {
                            "format": "mso_mdoc",
                            "scope": "test_scope",
                            "doctype": "org.iso.18013.5.1.mDL",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                            },
                            "vct": "TestVCT"
                        }
                    }
                }
                """;

        CredentialIssuerWellKnownResponse result = parser.parse(json);

        CredentialsSupportedResponse cred = result.getCredentialConfigurationsSupported().get("TestCred");
        assertNotNull(cred);
        assertNull(cred.getDisplay());
        assertNull(cred.getClaims());
        assertEquals("mso_mdoc", cred.getFormat());
        assertEquals("org.iso.18013.5.1.mDL", cred.getDoctype());
        assertNull(cred.getCredentialDefinition());
        assertNull(result.getNonceEndpoint());
    }

    @Test
    void shouldMapAllFieldsFromV1Config() throws IOException {
        String json = """
                {
                    "credential_issuer": "https://issuer.example.com",
                    "authorization_servers": ["https://auth1.com", "https://auth2.com"],
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "nonce_endpoint": "https://issuer.example.com/nonce",
                    "credential_configurations_supported": {
                        "Cred1": {
                            "format": "ldp_vc",
                            "scope": "scope1",
                            "doctype": "doctype1",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]},
                                "cwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
                            },
                            "credential_metadata": {
                                "display": [
                                    {"name": "Credential One", "locale": "en"},
                                    {"name": "Credenziale Uno", "locale": "it"}
                                ],
                                "claims": [
                                    {"path": ["field1"], "display": [{"name": "Field 1", "locale": "en"}]},
                                    {"path": ["field2"], "display": [{"name": "Field 2", "locale": "en"}]}
                                ]
                            },
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
        assertNull(cred.getCredentialDefinition());
        assertEquals(2, cred.getDisplay().size());
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
                            "credential_metadata": {
                                "display": [{"name": "Cred1", "locale": "en"}]
                            }
                        },
                        "Cred2": {
                            "format": "mso_mdoc",
                            "scope": "scope2",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                            }
                        }
                    }
                }
                """;

        CredentialIssuerWellKnownResponse result = parser.parse(json);

        assertEquals(2, result.getCredentialConfigurationsSupported().size());
        assertNotNull(result.getCredentialConfigurationsSupported().get("Cred1").getDisplay());
        assertNull(result.getCredentialConfigurationsSupported().get("Cred2").getDisplay());
    }

    @Test
    void shouldParseV1ResponseWithCredentialMetadataButNoDisplay() throws IOException {
        String json = """
                {
                    "credential_issuer": "https://issuer.example.com",
                    "authorization_servers": ["https://auth.example.com"],
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "credential_configurations_supported": {
                        "TestCred": {
                            "format": "ldp_vc",
                            "scope": "test_scope",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                            },
                            "credential_metadata": {
                                "claims": [
                                    {"path": ["given_name"], "display": [{"name": "Given Name", "locale": "en"}]}
                                ]
                            }
                        }
                    }
                }
                """;

        CredentialIssuerWellKnownResponse result = parser.parse(json);

        CredentialsSupportedResponse cred = result.getCredentialConfigurationsSupported().get("TestCred");
        assertNotNull(cred);
        assertNull(cred.getDisplay());
        assertEquals("ldp_vc", cred.getFormat());
        assertNotNull(cred.getClaims());
        assertEquals(1, cred.getClaims().size());
    }

    @Test
    void shouldParseV1ArrayFormatClaims() throws IOException {
        String json = """
                {
                    "credential_issuer": "https://issuer.example.com",
                    "authorization_servers": ["https://auth.example.com"],
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "nonce_endpoint": "https://issuer.example.com/nonce",
                    "credential_configurations_supported": {
                        "EmployeeCred": {
                            "format": "vc+sd-jwt",
                            "scope": "employee.read",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                            },
                            "vct": "EmployeeCredential",
                            "credential_metadata": {
                                "display": [{"name": "Employee Credential", "locale": "en"}],
                                "claims": [
                                    {"path": ["employeeId"], "display": [{"name": "Employee ID", "locale": "en"}]},
                                    {"path": ["name"], "display": [{"name": "Name", "locale": "en"}, {"name": "Nombre", "locale": "es"}]},
                                    {"path": ["address", "city"], "display": [{"name": "City", "locale": "en"}]}
                                ]
                            }
                        }
                    }
                }
                """;

        CredentialIssuerWellKnownResponse result = parser.parse(json);

        CredentialsSupportedResponse cred = result.getCredentialConfigurationsSupported().get("EmployeeCred");
        assertNotNull(cred);
        assertNotNull(cred.getClaims());
        assertEquals(3, cred.getClaims().size());

        assertTrue(cred.getClaims().containsKey("employeeId"));
        assertTrue(cred.getClaims().containsKey("name"));
        assertTrue(cred.getClaims().containsKey("city"));

        Map<String, Object> nameClaimValue = (Map<String, Object>) cred.getClaims().get("name");
        assertNotNull(nameClaimValue.get("display"));
        List<Map<String, String>> nameDisplays = (List<Map<String, String>>) nameClaimValue.get("display");
        assertEquals(2, nameDisplays.size());
        assertEquals("Name", nameDisplays.get(0).get("name"));
    }

    @Test
    void shouldUseLastPathElementAsClaimKey() throws IOException {
        String json = """
                {
                    "credential_issuer": "https://issuer.example.com",
                    "authorization_servers": ["https://auth.example.com"],
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "credential_configurations_supported": {
                        "TestCred": {
                            "format": "vc+sd-jwt",
                            "scope": "test.read",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                            },
                            "credential_metadata": {
                                "display": [{"name": "Test", "locale": "en"}],
                                "claims": [
                                    {"path": ["org.iso.18013.5.1", "given_name"], "display": [{"name": "Given Name", "locale": "en"}]},
                                    {"path": ["org.iso.18013.5.1.aamva", "organ_donor"]}
                                ]
                            }
                        }
                    }
                }
                """;

        CredentialIssuerWellKnownResponse result = parser.parse(json);

        CredentialsSupportedResponse cred = result.getCredentialConfigurationsSupported().get("TestCred");
        assertNotNull(cred.getClaims());
        assertEquals(2, cred.getClaims().size());
        assertTrue(cred.getClaims().containsKey("given_name"));
        assertTrue(cred.getClaims().containsKey("organ_donor"));
    }

    @Test
    void shouldReturnNullClaimsWhenClaimsArrayIsEmpty() throws IOException {
        String json = """
                {
                    "credential_issuer": "https://issuer.example.com",
                    "authorization_servers": ["https://auth.example.com"],
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "credential_configurations_supported": {
                        "TestCred": {
                            "format": "vc+sd-jwt",
                            "scope": "test.read",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                            },
                            "credential_metadata": {
                                "display": [{"name": "Test", "locale": "en"}],
                                "claims": []
                            }
                        }
                    }
                }
                """;

        CredentialIssuerWellKnownResponse result = parser.parse(json);

        assertNull(result.getCredentialConfigurationsSupported().get("TestCred").getClaims());
    }

    @Test
    void shouldSkipClaimEntriesWithEmptyPath() throws IOException {
        String json = """
                {
                    "credential_issuer": "https://issuer.example.com",
                    "authorization_servers": ["https://auth.example.com"],
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "credential_configurations_supported": {
                        "TestCred": {
                            "format": "vc+sd-jwt",
                            "scope": "test.read",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                            },
                            "credential_metadata": {
                                "display": [{"name": "Test", "locale": "en"}],
                                "claims": [
                                    {"path": [], "display": [{"name": "Empty Path", "locale": "en"}]},
                                    {"path": ["valid_field"], "display": [{"name": "Valid", "locale": "en"}]}
                                ]
                            }
                        }
                    }
                }
                """;

        CredentialIssuerWellKnownResponse result = parser.parse(json);

        Map<String, Object> claims = result.getCredentialConfigurationsSupported().get("TestCred").getClaims();
        assertNotNull(claims);
        assertEquals(1, claims.size());
        assertTrue(claims.containsKey("valid_field"));
    }

    @Test
    void shouldReturnNullClaimsWhenAllEntriesAreSkipped() throws IOException {
        String json = """
                {
                    "credential_issuer": "https://issuer.example.com",
                    "authorization_servers": ["https://auth.example.com"],
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "credential_configurations_supported": {
                        "TestCred": {
                            "format": "vc+sd-jwt",
                            "scope": "test.read",
                            "proof_types_supported": {
                                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                            },
                            "credential_metadata": {
                                "display": [{"name": "Test", "locale": "en"}],
                                "claims": [
                                    {"path": [], "display": [{"name": "No Path", "locale": "en"}]},
                                    {"display": [{"name": "Missing Path", "locale": "en"}]},
                                    {"path": ["ns", null], "display": [{"name": "Null Key", "locale": "en"}]}
                                ]
                            }
                        }
                    }
                }
                """;

        CredentialIssuerWellKnownResponse result = parser.parse(json);

        assertNull(result.getCredentialConfigurationsSupported().get("TestCred").getClaims());
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
        V1WellknownParser throwingParser = new V1WellknownParser(objectMapper, new ThrowingValidator());

        CredentialIssuerWellKnownResponse response = new CredentialIssuerWellKnownResponse();
        Validator noOpValidator = new NoOpValidator();

        assertThrows(InvalidWellknownResponseException.class,
                () -> throwingParser.validate(response, noOpValidator));
    }

    private static class ThrowingValidator extends V1CredentialIssuerWellknownResponseValidator {
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
