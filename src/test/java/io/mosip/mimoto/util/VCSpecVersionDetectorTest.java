package io.mosip.mimoto.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.mosip.mimoto.constant.VCSpecificationVersion;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VCSpecVersionDetectorTest {

    private VCSpecVersionDetector detector;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        detector = new VCSpecVersionDetector();
        objectMapper = new ObjectMapper();
    }

    static Stream<String> v1JsonInputs() {
        return Stream.of(
            """
            {"nonce_endpoint": "https://example.com/nonce"}
            """,
            """
            {
                "credential_configurations_supported": {
                    "cred1": {
                        "credential_metadata": {"display": []}
                    }
                }
            }
            """,
            """
            {
                "credential_configurations_supported": {
                    "cred1": {
                        "format": "ldp_vc"
                    }
                }
            }
            """,
            """
            {"credential_issuer": "https://example.com"}
            """,
            """
            {"credential_configurations_supported": "not_an_object"}
            """,
            """
            {
                "nonce_endpoint": "https://example.com/nonce",
                "credential_configurations_supported": {
                    "cred1": {
                        "credential_metadata": {"display": []},
                        "display": [{"name": "Test"}]
                    }
                }
            }
            """,
            """
            {
                "credential_configurations_supported": {
                    "cred1": {
                        "credential_metadata": {"display": []},
                        "display": [{"name": "Test"}]
                    }
                }
            }
            """,
            """
            {
                "credential_configurations_supported": {
                    "cred1": {"format": "ldp_vc"},
                    "cred2": {"credential_metadata": {"display": []}}
                }
            }
            """,
            """
            {"credential_configurations_supported": {}}
            """
        );
    }

    @ParameterizedTest
    @MethodSource("v1JsonInputs")
    void detectVersionReturnsV1ForVaryingInputs(String json) throws Exception {
        JsonNode node = objectMapper.readTree(json);
        assertEquals(VCSpecificationVersion.V1, detector.detectVersion(node));
    }

    @Test
    void shouldFallThroughWhenNonceEndpointIsBlank() throws Exception {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("nonce_endpoint", "");
        root.putObject("credential_configurations_supported")
                .putObject("cred1").put("display", "something");

        assertEquals(VCSpecificationVersion.DRAFT_13, detector.detectVersion(root));
    }

    @Test
    void shouldDetectDraft13WhenDisplayExistsInConfiguration() throws Exception {
        JsonNode node = objectMapper.readTree("""
                {
                    "credential_configurations_supported": {
                        "cred1": {
                            "display": [{"name": "Test"}]
                        }
                    }
                }
                """);
        assertEquals(VCSpecificationVersion.DRAFT_13, detector.detectVersion(node));
    }

    @Test
    void shouldDefaultToV1ForEmptyResponse() throws Exception {
        JsonNode node = objectMapper.readTree("{}");
        assertEquals(VCSpecificationVersion.V1, detector.detectVersion(node));
    }

    @Test
    void shouldCheckAllConfigurationsForDisplay() throws Exception {
        JsonNode node = objectMapper.readTree("""
                {
                    "credential_configurations_supported": {
                        "cred1": {"format": "ldp_vc"},
                        "cred2": {"display": [{"name": "Test"}]}
                    }
                }
                """);
        assertEquals(VCSpecificationVersion.DRAFT_13, detector.detectVersion(node));
    }
}
