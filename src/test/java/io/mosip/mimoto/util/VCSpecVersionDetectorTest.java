package io.mosip.mimoto.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.mosip.mimoto.constant.VCSpecificationVersion;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VCSpecVersionDetectorTest {

    private VCSpecVersionDetector detector;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        detector = new VCSpecVersionDetector();
        objectMapper = new ObjectMapper();
    }

    @Test
    void shouldDetectV1WhenNonceEndpointIsPresent() throws Exception {
        JsonNode node = objectMapper.readTree("""
                {"nonce_endpoint": "https://example.com/nonce"}
                """);
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
    void shouldDetectV1WhenCredentialMetadataExistsInConfiguration() throws Exception {
        JsonNode node = objectMapper.readTree("""
                {
                    "credential_configurations_supported": {
                        "cred1": {
                            "credential_metadata": {"display": []}
                        }
                    }
                }
                """);
        assertEquals(VCSpecificationVersion.V1, detector.detectVersion(node));
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
    void shouldDefaultToV1WhenNoIndicatorsPresent() throws Exception {
        JsonNode node = objectMapper.readTree("""
                {
                    "credential_configurations_supported": {
                        "cred1": {
                            "format": "ldp_vc"
                        }
                    }
                }
                """);
        assertEquals(VCSpecificationVersion.V1, detector.detectVersion(node));
    }

    @Test
    void shouldDefaultToV1WhenConfigurationsSupportedIsNull() throws Exception {
        JsonNode node = objectMapper.readTree("""
                {"credential_issuer": "https://example.com"}
                """);
        assertEquals(VCSpecificationVersion.V1, detector.detectVersion(node));
    }

    @Test
    void shouldDefaultToV1WhenConfigurationsSupportedIsNotAnObject() throws Exception {
        JsonNode node = objectMapper.readTree("""
                {"credential_configurations_supported": "not_an_object"}
                """);
        assertEquals(VCSpecificationVersion.V1, detector.detectVersion(node));
    }

    @Test
    void shouldDefaultToV1ForEmptyResponse() throws Exception {
        JsonNode node = objectMapper.readTree("{}");
        assertEquals(VCSpecificationVersion.V1, detector.detectVersion(node));
    }

    @Test
    void shouldPrioritizeNonceEndpointOverCredentialMetadata() throws Exception {
        JsonNode node = objectMapper.readTree("""
                {
                    "nonce_endpoint": "https://example.com/nonce",
                    "credential_configurations_supported": {
                        "cred1": {
                            "credential_metadata": {"display": []},
                            "display": [{"name": "Test"}]
                        }
                    }
                }
                """);
        assertEquals(VCSpecificationVersion.V1, detector.detectVersion(node));
    }

    @Test
    void shouldPrioritizeCredentialMetadataOverDisplay() throws Exception {
        JsonNode node = objectMapper.readTree("""
                {
                    "credential_configurations_supported": {
                        "cred1": {
                            "credential_metadata": {"display": []},
                            "display": [{"name": "Test"}]
                        }
                    }
                }
                """);
        assertEquals(VCSpecificationVersion.V1, detector.detectVersion(node));
    }

    @Test
    void shouldCheckAllConfigurationsForCredentialMetadata() throws Exception {
        JsonNode node = objectMapper.readTree("""
                {
                    "credential_configurations_supported": {
                        "cred1": {"format": "ldp_vc"},
                        "cred2": {"credential_metadata": {"display": []}}
                    }
                }
                """);
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

    @Test
    void shouldDefaultToV1WhenConfigurationsSupportedIsEmptyObject() throws Exception {
        JsonNode node = objectMapper.readTree("""
                {"credential_configurations_supported": {}}
                """);
        assertEquals(VCSpecificationVersion.V1, detector.detectVersion(node));
    }
}
