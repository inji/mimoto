package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.repository.ProofSigningKeyRepository;
import io.mosip.mimoto.service.impl.CredentialRequestServiceImpl;
import io.mosip.mimoto.service.impl.LdpVcCredentialFormatHandler;
import io.mosip.mimoto.util.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.mockito.ArgumentCaptor;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {CredentialRequestServiceImpl.class})
@TestPropertySource(locations = "classpath:application-test.properties")
public class CredentialRequestServiceTest {
    @Autowired
    private CredentialRequestServiceImpl credentialRequestServiceImpl;

    @MockBean
    private ProofSigningKeyRepository proofSigningKeyRepository;

    @MockBean
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @MockBean
    private CredentialFormatHandlerFactory credentialFormatHandlerFactory;

    @MockBean
    private KeyPairRetrievalService keyPairService;

    private final MockedStatic<SigningKeyUtil> keyGenerationUtilMockedStatic = Mockito.mockStatic(SigningKeyUtil.class, Mockito.withSettings().defaultAnswer(Mockito.CALLS_REAL_METHODS));

    IssuerDTO issuerDTO;
    String issuerId;

    @Before
    public void setUp() {
        issuerId = "issuer1";
        issuerDTO = getIssuerConfigDTO(issuerId);
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(new LdpVcCredentialFormatHandler());
    }

    @After
    public void tearDown() {
        if(keyGenerationUtilMockedStatic != null) {
            keyGenerationUtilMockedStatic.close();
        }
    }

    @Test
    public void shouldHandleNullContextInCredentialSupportedResponse() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        credentialsSupportedResponse.getCredentialDefinition().setContext(null);

        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");
        issuerWellKnownResponse.setCredentialConfigurationsSupported(
                Map.of("CredentialType1", credentialsSupportedResponse)
        );

        VCCredentialRequest result = credentialRequestServiceImpl.buildRequest(
                issuerDTO,
                "CredentialType1",
                issuerWellKnownResponse,
                "test-cnonce",
                "walletId",
                "walletKey",
                false
        );

        assertNotNull(result.getCredentialDefinition().getContext());
        assertEquals("https://www.w3.org/2018/credentials/v1", result.getCredentialDefinition().getContext().getFirst());
    }

    @Test
    public void shouldHandleEmptyContextInCredentialSupportedResponse() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");

        // Set an empty list as context
        credentialsSupportedResponse.getCredentialDefinition().setContext(List.of());

        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");
        issuerWellKnownResponse.setCredentialConfigurationsSupported(
                Map.of("CredentialType1", credentialsSupportedResponse)
        );
        VCCredentialRequest result = credentialRequestServiceImpl.buildRequest(
                issuerDTO,
                "CredentialType1",
                issuerWellKnownResponse,
                "test-cnonce",
                "walletId",
                "walletKey",
                false
        );

        assertNotNull(result.getCredentialDefinition().getContext());
        assertEquals("https://www.w3.org/2018/credentials/v1", result.getCredentialDefinition().getContext().getFirst());
    }


    @Test
    public void shouldHandleExistingContextWithSpecificValue() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");

        // Set context with a specific value
        credentialsSupportedResponse.getCredentialDefinition().setContext(List.of("https://www.w3.org/ns/credentials/v2"));

        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");
        issuerWellKnownResponse.setCredentialConfigurationsSupported(
                Map.of("CredentialType1", credentialsSupportedResponse)
        );

        VCCredentialRequest result = credentialRequestServiceImpl.buildRequest(
                issuerDTO,
                "CredentialType1",
                issuerWellKnownResponse,
                "test-cnonce",
                "walletId",
                "walletKey",
                false
        );

        assertNotNull(result.getCredentialDefinition().getContext());
        assertEquals("https://www.w3.org/ns/credentials/v2", result.getCredentialDefinition().getContext().getFirst());
    }

    @Test
    public void shouldReturnFallbackAlgorithmWhenJwtProofTypeOfProofTypesSupportedIsNull() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");
        issuerWellKnownResponse.setCredentialConfigurationsSupported(
                Map.of("CredentialType1", credentialsSupportedResponse)
        );
        credentialsSupportedResponse.getProofTypesSupported().put("jwt", null);


        credentialRequestServiceImpl.buildRequest(
                issuerDTO,
                "CredentialType1",
                issuerWellKnownResponse,
                "test-cnonce",
                "walletId",
                "walletKey",
                false
        );


        ArgumentCaptor<SigningAlgorithm> argumentCaptor = ArgumentCaptor.forClass(SigningAlgorithm.class);
        keyGenerationUtilMockedStatic.verify(() -> SigningKeyUtil.generateKeyPair(argumentCaptor.capture()));
        SigningAlgorithm capturedAlgorithm = argumentCaptor.getValue();
        assertEquals(SigningAlgorithm.ED25519, capturedAlgorithm);
    }

    @Test
    public void shouldReturnFallbackAlgorithmWhenJwtProofTypeOfProofTypesSupportedIsEmpty() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");
        issuerWellKnownResponse.setCredentialConfigurationsSupported(
                Map.of("CredentialType1", credentialsSupportedResponse)
        );
        ProofTypesSupported proofTypesSupported = new ProofTypesSupported();
        proofTypesSupported.setProofSigningAlgValuesSupported(Collections.emptyList());
        credentialsSupportedResponse.getProofTypesSupported().put("jwt", proofTypesSupported);

        credentialRequestServiceImpl.buildRequest(
                issuerDTO,
                "CredentialType1",
                issuerWellKnownResponse,
                "test-cnonce",
                "walletId",
                "walletKey",
                false
        );


        ArgumentCaptor<SigningAlgorithm> argumentCaptor = ArgumentCaptor.forClass(SigningAlgorithm.class);
        keyGenerationUtilMockedStatic.verify(() -> SigningKeyUtil.generateKeyPair(argumentCaptor.capture()));
        SigningAlgorithm capturedAlgorithm = argumentCaptor.getValue();
        assertEquals(SigningAlgorithm.ED25519, capturedAlgorithm);
    }

    @Test
    public void shouldUseHighestPriorityAlgorithmInPredefinedSigningAlgoPrioritySetWhichIsAlsoSupportedByIssuer() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");
        issuerWellKnownResponse.setCredentialConfigurationsSupported(
                Map.of("CredentialType1", credentialsSupportedResponse)
        );
        credentialsSupportedResponse.getProofTypesSupported().get("jwt").setProofSigningAlgValuesSupported(List.of("es256k"));


        credentialRequestServiceImpl.buildRequest(
                issuerDTO,
                "CredentialType1",
                issuerWellKnownResponse,
                "test-cnonce",
                "walletId",
                "walletKey",
                false
        );


        ArgumentCaptor<SigningAlgorithm> argumentCaptor = ArgumentCaptor.forClass(SigningAlgorithm.class);
        keyGenerationUtilMockedStatic.verify(() -> SigningKeyUtil.generateKeyPair(argumentCaptor.capture()));
        SigningAlgorithm capturedAlgorithm = argumentCaptor.getValue();
        assertEquals(SigningAlgorithm.ES256K, capturedAlgorithm);
    }

    @Test
    public void shouldUseFallbackPrioritySigningAlgorithmIfNoneOfIssuerSupportedAlgoAreSupportedByMimto() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");
        issuerWellKnownResponse.setCredentialConfigurationsSupported(
                Map.of("CredentialType1", credentialsSupportedResponse)
        );
        credentialsSupportedResponse.getProofTypesSupported().get("jwt").setProofSigningAlgValuesSupported(List.of("ps256"));


        credentialRequestServiceImpl.buildRequest(
                issuerDTO,
                "CredentialType1",
                issuerWellKnownResponse,
                "test-cnonce",
                "walletId",
                "walletKey",
                false
        );


        ArgumentCaptor<SigningAlgorithm> argumentCaptor = ArgumentCaptor.forClass(SigningAlgorithm.class);
        keyGenerationUtilMockedStatic.verify(() -> SigningKeyUtil.generateKeyPair(argumentCaptor.capture()));
        SigningAlgorithm capturedAlgorithm = argumentCaptor.getValue();
        assertEquals(SigningAlgorithm.ED25519, capturedAlgorithm);
    }
}