package io.mosip.mimoto.util;

import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.CredentialDefinitionResponseDto;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.dto.mimoto.Draft13VCCredentialRequest;
import io.mosip.mimoto.dto.mimoto.VCCredentialRequestProof;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class Draft13CredentialRequestBuilderTest {

    @InjectMocks
    private Draft13CredentialRequestBuilder builder;

    private CredentialsSupportedResponse credentialsSupportedResponse;
    private CredentialDefinitionResponseDto credentialDefinition;
    private VCCredentialRequestProof proof;

    @BeforeEach
    void setUp() {
        credentialsSupportedResponse = new CredentialsSupportedResponse();
        credentialDefinition = new CredentialDefinitionResponseDto();
        proof = VCCredentialRequestProof.builder()
                .proofType("jwt")
                .jwt("sample.jwt.token")
                .build();
    }

    @Test
    void buildCredentialRequest_LdpVcFormatWithValidContext_ReturnsCorrectRequest() {
        List<String> types = Arrays.asList("VerifiableCredential", "IdentityCredential");
        List<String> context = Arrays.asList("https://www.w3.org/2018/credentials/v1", "https://example.com/contexts/identity/v1");

        credentialDefinition.setType(types);
        credentialDefinition.setContext(context);
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinition);

        Draft13VCCredentialRequest result = builder.buildCredentialRequest(
                CredentialFormat.LDP_VC.getFormat(), proof, credentialsSupportedResponse);

        assertNotNull(result);
        assertEquals(CredentialFormat.LDP_VC.getFormat(), result.getFormat());
        assertEquals(proof, result.getProof());
        assertNotNull(result.getCredentialDefinition());
        assertEquals(types, result.getCredentialDefinition().getType());
        assertEquals(context, result.getCredentialDefinition().getContext());
    }

    @Test
    void buildCredentialRequest_LdpVcFormatWithNullContext_UsesDefaultContext() {
        List<String> types = Arrays.asList("VerifiableCredential", "IdentityCredential");

        credentialDefinition.setType(types);
        credentialDefinition.setContext(null);
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinition);

        Draft13VCCredentialRequest result = builder.buildCredentialRequest(
                CredentialFormat.LDP_VC.getFormat(), proof, credentialsSupportedResponse);

        assertNotNull(result);
        assertNotNull(result.getCredentialDefinition());
        assertEquals(types, result.getCredentialDefinition().getType());
        assertEquals(List.of("https://www.w3.org/2018/credentials/v1"), result.getCredentialDefinition().getContext());
    }

    @Test
    void buildCredentialRequest_LdpVcFormatWithEmptyContext_UsesDefaultContext() {
        List<String> types = Arrays.asList("VerifiableCredential", "IdentityCredential");

        credentialDefinition.setType(types);
        credentialDefinition.setContext(new ArrayList<>());
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinition);

        Draft13VCCredentialRequest result = builder.buildCredentialRequest(
                CredentialFormat.LDP_VC.getFormat(), proof, credentialsSupportedResponse);

        assertNotNull(result);
        assertNotNull(result.getCredentialDefinition());
        assertEquals(types, result.getCredentialDefinition().getType());
        assertEquals(List.of("https://www.w3.org/2018/credentials/v1"), result.getCredentialDefinition().getContext());
    }

    @Test
    void buildCredentialRequest_SdJwtFormat_ReturnsCorrectRequest() {
        credentialsSupportedResponse.setVct("IdentityCredential");

        Draft13VCCredentialRequest result = builder.buildCredentialRequest(
                CredentialFormat.VC_SD_JWT.getFormat(), proof, credentialsSupportedResponse);

        assertNotNull(result);
        assertEquals(CredentialFormat.VC_SD_JWT.getFormat(), result.getFormat());
        assertEquals(proof, result.getProof());
        assertEquals("IdentityCredential", result.getVct());
    }

    @Test
    void buildCredentialRequest_DcSdJwtFormat_ReturnsCorrectRequest() {
        credentialsSupportedResponse.setVct("IdentityCredential");

        Draft13VCCredentialRequest result = builder.buildCredentialRequest(
                CredentialFormat.DC_SD_JWT.getFormat(), proof, credentialsSupportedResponse);

        assertNotNull(result);
        assertEquals(CredentialFormat.DC_SD_JWT.getFormat(), result.getFormat());
        assertEquals(proof, result.getProof());
        assertEquals("IdentityCredential", result.getVct());
    }

    @Test
    void buildCredentialRequest_UnsupportedFormat_ThrowsIllegalArgumentException() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            builder.buildCredentialRequest("UNSUPPORTED_FORMAT", proof, credentialsSupportedResponse);
        });

        assertEquals("Unsupported credential format: UNSUPPORTED_FORMAT", exception.getMessage());
    }
}