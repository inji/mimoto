package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.openID4VP.constants.SpecVersion;
import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.model.CredentialMetadata;
import io.mosip.mimoto.service.impl.CredentialMatchingServiceImpl;
import io.mosip.mimoto.service.impl.OpenID4VPService;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.*;
import io.mosip.openID4VP.dcql.query.ClaimValue;
import io.mosip.openID4VP.dcql.query.ClaimsQuery;
import io.mosip.openID4VP.dcql.query.CredentialQuery;
import io.mosip.openID4VP.dcql.query.CredentialSetQuery;
import io.mosip.openID4VP.dcql.query.DCQLQuery;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class CredentialMatchingServiceTest {

    @InjectMocks
    private CredentialMatchingServiceImpl credentialMatchingService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private WalletCredentialService walletCredentialService;

    @Mock
    private DataProtectionService dataProtectionService;

    @Mock
    private IssuersService issuersService;

    @Mock
    private OpenID4VPService openID4VPService;

    @Mock
    private CredentialFormatHandlerFactory credentialFormatHandlerFactory;

    @Mock
    private CredentialFormatHandler credentialFormatHandler;

    private VerifiablePresentationSessionData sessionData;
    private String walletId;
    private String base64Key;
    private PresentationDefinition presentationDefinition;
    private List<DecryptedCredentialDTO> walletCredentials;

    @Before
    public void setUp() throws JsonProcessingException {
        walletId = "test-wallet-id";
        base64Key = "test-base64-key";
        sessionData = new VerifiablePresentationSessionData();
        presentationDefinition = createMockPresentationDefinition();
        walletCredentials = createMockWalletCredentials();

        when(credentialFormatHandlerFactory.getHandler(eq("ldp_vc"))).thenReturn(credentialFormatHandler);
        when(credentialFormatHandlerFactory.getHandler(eq(CredentialFormat.VC_SD_JWT.getFormat()))).thenReturn(credentialFormatHandler);

        when(credentialFormatHandler.extractAllCredentialProperties(any(VCCredentialResponse.class)))
                .thenAnswer(invocation -> {
                    VCCredentialResponse vc = invocation.getArgument(0);
                    String format = vc.getFormat();

                    if (CredentialFormat.isSdJwt(format)) {
                        Map<String, Object> publicClaims = new LinkedHashMap<>();
                        publicClaims.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
                        Map<String, Map<String, Object>> result = new LinkedHashMap<>();
                        result.put("publicClaims", publicClaims);
                        result.put("sdClaims", new LinkedHashMap<>());
                        return result;
                    }

                    Object credential = vc.getCredential();
                    if (credential instanceof Map) {
                        return new LinkedHashMap<>((Map<?, ?>) credential);
                    }
                    return new LinkedHashMap<>();
                });
    }

    @Test
    public void testGetMatchingCredentialsSuccess() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());
        IssuerConfig issuerConfig = createMockIssuerConfig();
        when(issuersService.getIssuerConfig(anyString(), anyString()))
                .thenReturn(issuerConfig);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        assertNotNull(result.getMatchingCredentials());
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());

        verify(openID4VPService).resolvePresentationDefinition(any(), any(), anyBoolean());
        verify(walletCredentialService).getDecryptedCredentials(eq(walletId), any());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetMatchingCredentialsNullWalletId() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);

        // Act
        credentialMatchingService.getMatchingCredentials(sessionData, null, base64Key);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetMatchingCredentialsEmptyWalletId() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);

        // Act
        credentialMatchingService.getMatchingCredentials(sessionData, "", base64Key);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetMatchingCredentialsNullBase64Key() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);

        // Act
        credentialMatchingService.getMatchingCredentials(sessionData, walletId, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetMatchingCredentialsEmptyInputDescriptors() throws Exception {
        // Arrange
        PresentationDefinition emptyPd = new PresentationDefinition("test", Collections.emptyList(), null, null, null);
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(emptyPd);

        // Act
        credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetMatchingCredentialsEmptyInputDescriptorId() throws Exception {
        // Arrange
        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test", Arrays.asList(descriptor), null, null, null);
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);

        // Act
        credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetMatchingCredentialsWhitespaceWalletId() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);

        // Act
        credentialMatchingService.getMatchingCredentials(sessionData, "   ", base64Key);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetMatchingCredentialsWhitespaceBase64Key() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);

        // Act
        credentialMatchingService.getMatchingCredentials(sessionData, walletId, "   ");
    }

    @Test
    public void testGetMatchingCredentialsEmptyWalletCredentials() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Collections.emptyList());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
        assertTrue(result.getMatchingCredentials().isEmpty());
        assertFalse(result.getMatchingCredentialsResponse().getMissingClaims().isEmpty());
        assertNull(result.getMatchingCredentialsResponse().getQueryGroups());
    }

    @Test
    public void testGetMatchingCredentialsDecryptionFailure() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(walletCredentials);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertTrue(result.getMatchingCredentials().isEmpty());
    }

    @Test
    public void testGetMatchingCredentialsWithConstraints() throws Exception {
        // Arrange
        PresentationDefinition pdWithConstraints = createMockPresentationDefinitionWithConstraints();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithConstraints);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
    }

    @Test
    public void testGetMatchingCredentialsFormatMismatch() throws Exception {
        // Arrange
        PresentationDefinition pdWithFormat = createMockPresentationDefinitionWithSpecificFormat();
        List<DecryptedCredentialDTO> credentialsWithDifferentFormat = createMockWalletCredentialsWithSdJwtFormat();

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithFormat);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(credentialsWithDifferentFormat);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testGetMatchingCredentialsFormatMatchingWithProofType() throws Exception {
        // Arrange
        PresentationDefinition pdWithFormat = createMockPresentationDefinitionWithSpecificFormat();

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithFormat);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMatchingFormat());
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class)))
                .thenReturn(createMockVCCredentialPropertiesWithProof());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testGetMatchingCredentialsFormatMatchingWithoutProofType() throws Exception {
        // Arrange
        PresentationDefinition pdWithoutProofType = createMockPresentationDefinitionWithoutProofType();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithoutProofType);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testGetMatchingCredentialsFormatMatchingWithNullFormat() throws Exception {
        // Arrange
        PresentationDefinition pdWithNullFormat = createMockPresentationDefinitionWithNullFormat();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithNullFormat);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testGetMatchingCredentialsWithConstraintsMatching() throws Exception {
        // Arrange
        PresentationDefinition pdWithConstraints = createMockPresentationDefinitionWithConstraints();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithConstraints);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithSubject());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
    }

    @Test
    public void testGetMatchingCredentialsWithConstraintsNotMatching() throws Exception {
        // Arrange
        PresentationDefinition pdWithConstraints = createMockPresentationDefinitionWithConstraints();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithConstraints);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(walletCredentials);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
        assertFalse(result.getMatchingCredentialsResponse().getMissingClaims().isEmpty());
    }

    @Test
    public void testGetMatchingCredentialsWithNullConstraints() throws Exception {
        // Arrange
        PresentationDefinition pdWithNullConstraints = createMockPresentationDefinitionWithNullConstraints();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithNullConstraints);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testGetMatchingCredentialsWithEmptyFieldPaths() throws Exception {
        // Arrange
        PresentationDefinition pdWithEmptyPaths = createMockPresentationDefinitionWithEmptyPaths();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithEmptyPaths);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testGetMatchingCredentialsWithFilterNotMatching() throws Exception {
        // Arrange
        PresentationDefinition pdWithFilter = createMockPresentationDefinitionWithFilter();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithFilter);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(walletCredentials);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testGetMatchingCredentialsWithNullFilter() throws Exception {
        // Arrange
        PresentationDefinition pdWithNullFilter = createMockPresentationDefinitionWithNullFilter();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithNullFilter);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testGetMatchingCredentialsWithJsonPathErrors() throws Exception {
        // Arrange
        PresentationDefinition pdWithInvalidPath = createMockPresentationDefinitionWithInvalidPath();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithInvalidPath);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(walletCredentials);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testGetMatchingCredentialsWithSdJwtFormat() throws Exception {
        // Arrange
        PresentationDefinition pd = createMockPresentationDefinition();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithSdJwtFormat());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert - PD has no format constraint; SD-JWT credential with $.type satisfies the constraint
        assertNotNull(result);
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
        assertEquals(CredentialFormat.VC_SD_JWT.getFormat(),
                result.getMatchingCredentialsResponse().getAvailableCredentials().get(0).getFormat());
    }

    @Test
    public void testGetMatchingCredentialsWithDcSdJwtFormat() throws Exception {
        // Arrange
        PresentationDefinition pd = createMockPresentationDefinition();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        when(credentialFormatHandlerFactory.getHandler(eq(CredentialFormat.DC_SD_JWT.getFormat())))
                .thenReturn(credentialFormatHandler);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithDcSdJwtFormat());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert - dc+sd-jwt is handled like vc+sd-jwt and surfaces as an available credential
        assertNotNull(result);
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
        assertEquals(CredentialFormat.DC_SD_JWT.getFormat(),
                result.getMatchingCredentialsResponse().getAvailableCredentials().get(0).getFormat());
    }

    @Test
    public void testGetMatchingCredentialsWithIssuerConfigException() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());
        when(issuersService.getIssuerConfig(anyString(), anyString()))
                .thenThrow(new InvalidIssuerIdException());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
        assertEquals("Unknown Credential", 
                result.getMatchingCredentialsResponse().getAvailableCredentials().get(0).getCredentialTypeDisplayName());
    }

    @Test
    public void testGetMatchingCredentialsWithApiNotAccessibleException() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());
        when(issuersService.getIssuerConfig(anyString(), anyString()))
                .thenThrow(new ApiNotAccessibleException());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
        assertEquals("Unknown Credential", 
                result.getMatchingCredentialsResponse().getAvailableCredentials().get(0).getCredentialTypeDisplayName());
    }

    @Test
    public void testGetMatchingCredentialsWithMultipleDescriptors() throws Exception {
        // Arrange
        PresentationDefinition pdWithMultipleDescriptors = createMockPresentationDefinitionWithMultipleDescriptors();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithMultipleDescriptors);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMultipleCredentials());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
        Set<String> credentialIds = result.getMatchingCredentialsResponse().getAvailableCredentials()
                .stream().map(CredentialDTO::getCredentialId).collect(Collectors.toSet());
        assertEquals(2, credentialIds.size());
    }

    private PresentationDefinition createMockPresentationDefinition() {
        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
        return pd;
    }

    private PresentationDefinition createMockPresentationDefinitionWithConstraints() {
        Fields field1 = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Filter filter = new Filter("type", "String");
        Fields field2 = new Fields(Arrays.asList("$.credentialSubject.name"), null, null, null, filter, null);
        Constraints constraints = new Constraints(Arrays.asList(field1, field2), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor-with-constraints", null, null, null, constraints);
        return new PresentationDefinition("test-presentation-definition-with-constraints", Arrays.asList(descriptor), null, null, null);
    }

    private PresentationDefinition createMockPresentationDefinitionWithSpecificFormat() {
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        Map<String, List<String>> ldpVcFormat = new HashMap<>();
        ldpVcFormat.put("proof_type", Arrays.asList("Ed25519Signature2020"));
        format.put("ldp_vc", ldpVcFormat);
        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, format, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
        return pd;
    }

    private List<DecryptedCredentialDTO> createMockWalletCredentials() throws JsonProcessingException {
        DecryptedCredentialDTO credential = new DecryptedCredentialDTO();
        credential.setId("test-credential-id");
        credential.setWalletId(walletId);

        VCCredentialProperties properties = new VCCredentialProperties();
        properties.setType(Arrays.asList("VerifiableCredential", "TestCredential"));
        VCCredentialResponse response = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(properties)
                .build();

        credential.setCredential(response);

        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("test-issuer-id");
        metadata.setCredentialType("TestCredential");
        credential.setCredentialMetadata(metadata);

            credential.setCreatedAt(Instant.now());
            credential.setUpdatedAt(Instant.now());

        return Arrays.asList(credential);
    }

    private VCCredentialResponse createMockVCCredentialResponse() {
        VCCredentialResponse response = new VCCredentialResponse();
        response.setFormat(CredentialFormat.LDP_VC.getFormat());

        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        credentialData.put("credentialSubject", createMockCredentialSubject());

        response.setCredential(credentialData);
        return response;
    }

    private VCCredentialResponse createMockVCCredentialResponseWithSubject() {
        VCCredentialResponse response = createMockVCCredentialResponse();
        @SuppressWarnings("unchecked")
        Map<String, Object> credentialData = (Map<String, Object>) response.getCredential();
        Map<String, Object> subject = new HashMap<>();
        subject.put("name", "John Doe");
        credentialData.put("credentialSubject", subject);
        return response;
    }

    private Map<String, Object> createMockCredentialSubject() {
        Map<String, Object> subject = new HashMap<>();
        subject.put("id", "did:example:123456789");
        subject.put("name", "Test Subject");
        return subject;
    }

    private Map<String, Object> createMockCredentialMap() {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        credentialMap.put("credentialSubject", createMockCredentialSubject());
        return credentialMap;
    }

    private IssuerConfig createMockIssuerConfig() {
        IssuerDTO issuerDTO = new IssuerDTO();
        DisplayDTO display = new DisplayDTO();
        display.setName("Test Issuer");
        LogoDTO logoDTO = new LogoDTO();
        logoDTO.setUrl("dsds");
        display.setLogo(logoDTO);
        issuerDTO.setDisplay(Collections.singletonList(display));
        CredentialsSupportedResponse credentialsSupportedResponse = new CredentialsSupportedResponse();
        CredentialSupportedDisplayResponse  credentialSupportedDisplayResponse   = new CredentialSupportedDisplayResponse();
        credentialSupportedDisplayResponse.setName("test");
        credentialSupportedDisplayResponse.setLogo(logoDTO);
        credentialsSupportedResponse.setDisplay(Collections.singletonList(credentialSupportedDisplayResponse));
        IssuerConfig config = new IssuerConfig(issuerDTO, new CredentialIssuerWellKnownResponse(), credentialsSupportedResponse);
        return config;
    }

    private PresentationDefinition createMockPresentationDefinitionWithoutProofType() {
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        Map<String, List<String>> ldpVcFormat = new HashMap<>();
        format.put("ldp_vc", ldpVcFormat);
        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, format, constraints);
        return new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
    }

    private PresentationDefinition createMockPresentationDefinitionWithNullFormat() {
        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        return new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
    }

    private PresentationDefinition createMockPresentationDefinitionWithNullConstraints() {
        Constraints constraints = new Constraints(null, null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        return new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
    }

    private PresentationDefinition createMockPresentationDefinitionWithEmptyPaths() {
        Fields field = new Fields(Collections.emptyList(), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        return new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
    }

    private PresentationDefinition createMockPresentationDefinitionWithFilter() {
        Filter filter = new Filter("John", "String");
        Fields field = new Fields(Arrays.asList("$.credentialSubject.name"), null, null, null, filter, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        return new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
    }

    private PresentationDefinition createMockPresentationDefinitionWithNullFilter() {
        Fields field = new Fields(Arrays.asList("$.credentialSubject.name"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        return new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
    }

    private PresentationDefinition createMockPresentationDefinitionWithInvalidPath() {
        Fields field = new Fields(Arrays.asList("$.invalid.path"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        return new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
    }

    private PresentationDefinition createMockPresentationDefinitionWithMultipleDescriptors() {
        Fields field1 = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints1 = new Constraints(Collections.singletonList(field1), null);
        InputDescriptor descriptor1 = new InputDescriptor("test-descriptor-1", null, null, null, constraints1);

        Fields field2 = new Fields(Arrays.asList("$.credentialSubject.id"), null, null, null, null, null);
        Constraints constraints2 = new Constraints(Collections.singletonList(field2), null);
        InputDescriptor descriptor2 = new InputDescriptor("test-descriptor-2", null, null, null, constraints2);

        return new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor1, descriptor2), null, null, null);
    }

    private List<DecryptedCredentialDTO> createMockWalletCredentialsWithMatchingFormat() throws JsonProcessingException {
        DecryptedCredentialDTO credential = new DecryptedCredentialDTO();
        credential.setId("test-credential-id");
        credential.setWalletId(walletId);

        VCCredentialResponse response = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(createMockCredentialMap())
                .build();

        credential.setCredential(response);

        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("test-issuer-id");
        metadata.setCredentialType("TestCredential");
        credential.setCredentialMetadata(metadata);
        credential.setCreatedAt(Instant.now());
        credential.setUpdatedAt(Instant.now());

        return Arrays.asList(credential);
    }

    private List<DecryptedCredentialDTO> createMockWalletCredentialsWithSubject() throws JsonProcessingException {
        DecryptedCredentialDTO credential = new DecryptedCredentialDTO();
        credential.setId("test-credential-id");
        credential.setWalletId(walletId);

        VCCredentialResponse response = createMockVCCredentialResponseWithSubject();
        credential.setCredential(response);

        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("test-issuer-id");
        metadata.setCredentialType("TestCredential");
        credential.setCredentialMetadata(metadata);
        credential.setCreatedAt(Instant.now());
        credential.setUpdatedAt(Instant.now());

        return Arrays.asList(credential);
    }

    private List<DecryptedCredentialDTO> createMockWalletCredentialsWithSdJwtFormat() throws JsonProcessingException {
        DecryptedCredentialDTO credential = new DecryptedCredentialDTO();
        credential.setId("test-credential-id");
        credential.setWalletId(walletId);

        VCCredentialResponse response = VCCredentialResponse.builder()
                .format(CredentialFormat.VC_SD_JWT.getFormat())
                .credential("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5IiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlRlc3RDcmVkZW50aWFsIl19.signature")
                .build();

        credential.setCredential(response);

        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("test-issuer-id");
        metadata.setCredentialType("TestCredential");
        credential.setCredentialMetadata(metadata);
        credential.setCreatedAt(Instant.now());
        credential.setUpdatedAt(Instant.now());

        return Arrays.asList(credential);
    }

    private List<DecryptedCredentialDTO> createMockWalletCredentialsWithDcSdJwtFormat() throws JsonProcessingException {
        DecryptedCredentialDTO credential = new DecryptedCredentialDTO();
        credential.setId("test-credential-id");
        credential.setWalletId(walletId);

        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("iss", "https://example.com");
        credentialData.put("sub", "did:example:123456789");
        credentialData.put("type", Arrays.asList("DataCredential", "TestCredential"));

        VCCredentialResponse response = VCCredentialResponse.builder()
                .format(CredentialFormat.DC_SD_JWT.getFormat())
                .credential(credentialData)
                .build();

        credential.setCredential(response);

        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("test-issuer-id");
        metadata.setCredentialType("TestCredential");
        credential.setCredentialMetadata(metadata);
        credential.setCreatedAt(Instant.now());
        credential.setUpdatedAt(Instant.now());

        return Arrays.asList(credential);
    }

    private List<DecryptedCredentialDTO> createMockWalletCredentialsWithMultipleCredentials() throws JsonProcessingException {
        DecryptedCredentialDTO credential1 = new DecryptedCredentialDTO();
        credential1.setId("test-credential-id-1");
        credential1.setWalletId(walletId);
        credential1.setCredential(createMockVCCredentialResponse());
        CredentialMetadata metadata1 = new CredentialMetadata();
        metadata1.setIssuerId("test-issuer-id-1");
        metadata1.setCredentialType("TestCredential1");
        credential1.setCredentialMetadata(metadata1);
        credential1.setCreatedAt(Instant.now());
        credential1.setUpdatedAt(Instant.now());

        DecryptedCredentialDTO credential2 = new DecryptedCredentialDTO();
        credential2.setId("test-credential-id-2");
        credential2.setWalletId(walletId);
        credential2.setCredential(createMockVCCredentialResponseWithSubject());
        CredentialMetadata metadata2 = new CredentialMetadata();
        metadata2.setIssuerId("test-issuer-id-2");
        metadata2.setCredentialType("TestCredential2");
        credential2.setCredentialMetadata(metadata2);
        credential2.setCreatedAt(Instant.now());
        credential2.setUpdatedAt(Instant.now());

        return Arrays.asList(credential1, credential2);
    }

    private VCCredentialProperties createMockVCCredentialPropertiesWithProof() {
        VCCredentialProperties properties = new VCCredentialProperties();
        properties.setType(Arrays.asList("VerifiableCredential", "TestCredential"));

        VCCredentialResponseProof proof = new VCCredentialResponseProof();
        proof.setType("Ed25519Signature2020");
        properties.setProof(proof);
        
        return properties;
    }

    private List<DecryptedCredentialDTO> createMockWalletCredentialsWithMapData() throws JsonProcessingException {
        DecryptedCredentialDTO credential = new DecryptedCredentialDTO();
        credential.setId("test-credential-id");
        credential.setWalletId(walletId);

        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        Map<String, Object> subject = new HashMap<>();
        subject.put("id", "did:example:123456789");
        subject.put("name", "John Doe");
        credentialData.put("credentialSubject", subject);

        VCCredentialResponse response = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(credentialData)
                .build();

        credential.setCredential(response);

        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("test-issuer-id");
        metadata.setCredentialType("TestCredential");
        credential.setCredentialMetadata(metadata);
        credential.setCreatedAt(Instant.now());
        credential.setUpdatedAt(Instant.now());

        return Arrays.asList(credential);
    }

    private List<DecryptedCredentialDTO> createMockWalletCredentialsWithSimpleFilterData() throws JsonProcessingException {
        DecryptedCredentialDTO credential = new DecryptedCredentialDTO();
        credential.setId("test-credential-id");
        credential.setWalletId(walletId);

        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        credentialData.put("name", "John Doe");
        credentialData.put("id", "did:example:123456789");

        VCCredentialResponse response = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(credentialData)
                .build();

        credential.setCredential(response);

        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("test-issuer-id");
        metadata.setCredentialType("TestCredential");
        credential.setCredentialMetadata(metadata);
        credential.setCreatedAt(Instant.now());
        credential.setUpdatedAt(Instant.now());

        return Arrays.asList(credential);
    }

    @Test
    public void testJsonPathEvaluationTypePathWithSampleData() throws Exception {
        // Arrange
        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("id", "did:rcw:2121a1df-29fe-496e-ae24-219dcOb3ac49");
        credentialData.put("type", Arrays.asList("VerifiableCredential", "LifeInsuranceCredential"));

        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        List<DecryptedCredentialDTO> credentials = createMockWalletCredentialsWithSampleData(credentialData);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(credentials);
        IssuerConfig mockIssuerConfig = createMockIssuerConfig();
        when(issuersService.getIssuerConfig(eq("test-issuer-id"), eq("TestCredential")))
                .thenReturn(mockIssuerConfig);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testJsonPathEvaluationNestedPath() throws Exception {
        // Arrange
        Map<String, Object> credentialData = new HashMap<>();
        Map<String, Object> credentialSubject = new HashMap<>();
        credentialSubject.put("name", "John Doe");
        credentialSubject.put("age", 30);
        credentialData.put("credentialSubject", credentialSubject);
        credentialData.put("type", Arrays.asList("VerifiableCredential", "IdentityCredential"));

        Fields field = new Fields(Arrays.asList("$.credentialSubject.name"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        List<DecryptedCredentialDTO> credentials = createMockWalletCredentialsWithSampleData(credentialData);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(credentials);
        IssuerConfig mockIssuerConfig = createMockIssuerConfig();
        when(issuersService.getIssuerConfig(eq("test-issuer-id"), eq("TestCredential")))
                .thenReturn(mockIssuerConfig);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testJsonPathEvaluationNonExistentPath() throws Exception {
        // Arrange
        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("id", "did:rcw:2121a1df-29fe-496e-ae24-219dcOb3ac49");
        credentialData.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));

        Fields field = new Fields(Arrays.asList("$.nonExistentField"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        List<DecryptedCredentialDTO> credentials = createMockWalletCredentialsWithSampleData(credentialData);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(credentials);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testJsonPathEvaluationComplexNestedStructure() throws Exception {
        // Arrange
        Map<String, Object> credentialData = new HashMap<>();
        Map<String, Object> credentialSubject = new HashMap<>();
        Map<String, Object> address = new HashMap<>();
        address.put("street", "123 Main St");
        address.put("city", "New York");
        credentialSubject.put("address", address);
        credentialSubject.put("name", "John Doe");
        credentialData.put("credentialSubject", credentialSubject);
        credentialData.put("type", Arrays.asList("VerifiableCredential", "IdentityCredential"));

        Fields field = new Fields(Arrays.asList("$.credentialSubject.address.city"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        List<DecryptedCredentialDTO> credentials = createMockWalletCredentialsWithSampleData(credentialData);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(credentials);
        IssuerConfig mockIssuerConfig = createMockIssuerConfig();
        when(issuersService.getIssuerConfig(eq("test-issuer-id"), eq("TestCredential")))
                .thenReturn(mockIssuerConfig);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testJsonPathEvaluationListIndexPath() throws Exception {
        // Arrange
        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("items", Arrays.asList("item1", "item2", "item3"));
        credentialData.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));

        Fields field = new Fields(Arrays.asList("$.items.1"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        List<DecryptedCredentialDTO> credentials = createMockWalletCredentialsWithSampleData(credentialData);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(credentials);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    private List<DecryptedCredentialDTO> createMockWalletCredentialsWithSampleData(Map<String, Object> credentialData) throws JsonProcessingException {
        DecryptedCredentialDTO credential = new DecryptedCredentialDTO();
        credential.setId("test-credential-id");
        credential.setWalletId(walletId);

        VCCredentialResponse response = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(credentialData)
                .build();

        credential.setCredential(response);

        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("test-issuer-id");
        metadata.setCredentialType("TestCredential");
        credential.setCredentialMetadata(metadata);
        credential.setCreatedAt(Instant.now());
        credential.setUpdatedAt(Instant.now());

        return Arrays.asList(credential);
    }

    @Test
    public void testGetMatchingCredentialsNullPresentationDefinitionFromService() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(null);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);
        });
        
        assertEquals("Presentation definition cannot be null", exception.getMessage());
    }

    @Test
    public void testExtractRequiredClaimsBlankPath() throws Exception {
        // Arrange
        Fields field = new Fields(Arrays.asList("   "), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);
        
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        
        List<DecryptedCredentialDTO> credentials = createMockWalletCredentialsWithMapData();
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(credentials);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
    }

    @Test
    public void testMatchesSdJwtFormatWhenAlgorithmMatchesCredentialIsSelected() throws Exception {
        // Arrange
        PresentationDefinition pd = createSdJwtPresentationDefinition(Arrays.asList("HS256"));
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);

        Map<String, Object> publicClaims = new LinkedHashMap<>();
        publicClaims.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        setupSdJwtHandlerMock(publicClaims, new LinkedHashMap<>());

        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Arrays.asList(createDecryptedSdJwtCredential(SD_JWT_HS256)));

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
        assertEquals(CredentialFormat.VC_SD_JWT.getFormat(),
                result.getMatchingCredentialsResponse().getAvailableCredentials().get(0).getFormat());
    }

    @Test
    public void testMatchesSdJwtFormatWhenAlgorithmDoesNotMatchCredentialNotSelected() throws Exception {
        // Arrange
        PresentationDefinition pd = createSdJwtPresentationDefinition(Arrays.asList("ES256"));
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Arrays.asList(createDecryptedSdJwtCredential(SD_JWT_HS256)));

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testMatchesSdJwtFormatWhenNoAlgValuesInFormatCredentialIsSelected() throws Exception {
        // Arrange
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        format.put(CredentialFormat.VC_SD_JWT.getFormat(), new HashMap<>());

        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, format, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        Map<String, Object> publicClaims = new LinkedHashMap<>();
        publicClaims.put("type", Arrays.asList("VerifiableCredential"));
        setupSdJwtHandlerMock(publicClaims, new LinkedHashMap<>());
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Arrays.asList(createDecryptedSdJwtCredential(SD_JWT_HS256)));

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert - no sd-jwt_alg_values constraint means any algorithm is acceptable
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testMatchesSdJwtFormatWhenCredentialIsNullCredentialNotSelected() throws Exception {
        // Arrange
        PresentationDefinition pd = createSdJwtPresentationDefinition(Arrays.asList("HS256"));
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Arrays.asList(createDecryptedSdJwtCredential(null)));

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testMatchesSdJwtFormatWhenCredentialIsNotStringCredentialNotSelected() throws Exception {
        // Arrange
        PresentationDefinition pd = createSdJwtPresentationDefinition(Arrays.asList("HS256"));
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);

        DecryptedCredentialDTO cred = new DecryptedCredentialDTO();
        cred.setId("sd-jwt-cred");
        cred.setWalletId(walletId);
        cred.setCredential(VCCredentialResponse.builder()
                .format(CredentialFormat.VC_SD_JWT.getFormat())
                .credential(Map.of("key", "value"))
                .build());
        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("test-issuer-id");
        metadata.setCredentialType("TestCredential");
        cred.setCredentialMetadata(metadata);
        cred.setCreatedAt(Instant.now());
        cred.setUpdatedAt(Instant.now());

        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Arrays.asList(cred));

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testMatchesSdJwtFormatWhenFormatConfigValueIsNullCredentialSelected() throws Exception {
        // Arrange - sd-jwt_alg_values key present but value is explicitly null → any alg acceptable
        Map<String, List<String>> sdJwtFormatConfig = new HashMap<>();
        sdJwtFormatConfig.put("sd-jwt_alg_values", null);
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        format.put(CredentialFormat.VC_SD_JWT.getFormat(), sdJwtFormatConfig);

        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, format, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Arrays.asList(createDecryptedSdJwtCredential(SD_JWT_HS256)));

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert - null alg list means no restriction, credential should be selected
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testMatchesSdJwtFormatWhenJwtHeaderMissingAlgCredentialNotSelected() throws Exception {
        // Arrange
        PresentationDefinition pd = createSdJwtPresentationDefinition(Arrays.asList("HS256"));
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Arrays.asList(createDecryptedSdJwtCredential(SD_JWT_NO_ALG)));

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testMatchesSdJwtFormatWhenEmptyJwtStringCredentialNotSelected() throws Exception {
        // Arrange
        PresentationDefinition pd = createSdJwtPresentationDefinition(Arrays.asList("HS256"));
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Arrays.asList(createDecryptedSdJwtCredential("   ")));

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testMatchesSdJwtFormatWhenJwtHeaderAlgIsNonStringCredentialNotSelected() throws Exception {
        // Arrange
        PresentationDefinition pd = createSdJwtPresentationDefinition(Arrays.asList("HS256"));
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Arrays.asList(createDecryptedSdJwtCredential(SD_JWT_NON_STRING_ALG)));

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testGetCredentialDataWhenSdJwtExtractsNullCredentialNotSelected() throws Exception {
        // Arrange
        Fields field = new Fields(Arrays.asList("$.name"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Arrays.asList(createDecryptedSdJwtCredential(SD_JWT_HS256)));
        when(credentialFormatHandler.extractAllCredentialProperties(any(VCCredentialResponse.class)))
                .thenReturn(null);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testGetCredentialDataWhenSdJwtFlattensPropertiesCredentialSelected() throws Exception {
        // Arrange
        Fields field = new Fields(Arrays.asList("$.name"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Arrays.asList(createDecryptedSdJwtCredential(SD_JWT_HS256)));

        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("name", "John");
        setupSdJwtHandlerMock(new LinkedHashMap<>(), sdClaims);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    
    @Test
    public void testBuildAvailableCredentialWhenSdJwtWithNullClaimsReturnsEmptyClaimLists() throws Exception {
        // Arrange
        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(null, null));

        // Assert
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        assertTrue(credential.getClaims().isEmpty());
        assertTrue(credential.getSdClaims().isEmpty());
        assertEquals(CredentialFormat.VC_SD_JWT.getFormat(), credential.getFormat());
    }

    @Test
    public void testBuildAvailableCredentialWhenSdJwtWithCredentialSubjectExtractsFromSubject() throws Exception {
        Map<String, Object> publicClaims = new LinkedHashMap<>();
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("name", "John");
        subject.put("age", 30);
        subject.put("_sd", Arrays.asList("hash1", "hash2"));
        Map<String, Object> address = new LinkedHashMap<>();
        address.put("street", "123 Main St");
        address.put("city", "NYC");
        subject.put("address", address);
        List<Map<String, Object>> contacts = Arrays.asList(
                createMapOf("type", "email", "value", "john@example.com"),
                createMapOf("type", "phone", "value", "555-1234"));
        subject.put("contacts", contacts);
        List<Object> privileges = Arrays.asList(
                createMapOf("vehicle_code", "C", "issue_date", "2020-01-01"));
        subject.put("privileges", privileges);
        List<Object> tags = new ArrayList<>();
        tags.add(createMapOf("code", "A", "label", "TagA"));
        tags.add(createMapOf("code", "B", "label", "TagB"));
        tags.add("plain-string");
        subject.put("tags", tags);
        List<Map<String, Object>> disjoint = Arrays.asList(
                createMapOf("alpha", 1),
                createMapOf("beta", 2));
        subject.put("disjoint", disjoint);
        publicClaims.put("credentialSubject", subject);

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(publicClaims, new LinkedHashMap<>()));

        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        assertTrue(credential.getClaims().contains("$.name"));
        assertTrue(credential.getClaims().contains("$.age"));
        assertTrue(credential.getClaims().contains("$.address.street"));
        assertTrue(credential.getClaims().contains("$.address.city"));
        assertTrue(credential.getClaims().contains("$.contacts"));
        assertFalse(credential.getClaims().contains("$.contacts.type"));
        assertFalse(credential.getClaims().contains("$.contacts.value"));
        assertTrue(credential.getClaims().contains("$.privileges"));
        assertTrue(credential.getClaims().contains("$.privileges.vehicle_code"));
        assertTrue(credential.getClaims().contains("$.privileges.issue_date"));
        assertTrue(credential.getClaims().contains("$.tags"));
        assertTrue(credential.getClaims().contains("$.tags.code"));
        assertTrue(credential.getClaims().contains("$.tags.label"));
        assertTrue(credential.getClaims().contains("$.disjoint"));
        assertTrue(credential.getClaims().contains("$.disjoint.alpha"));
        assertTrue(credential.getClaims().contains("$.disjoint.beta"));
        assertFalse(credential.getClaims().contains("$._sd"));
        assertFalse(credential.getClaims().contains("$.address"));
    }

    @Test
    public void testBuildAvailableCredentialWhenSdJwtWithoutCredentialSubjectRemovesMetadataAndExtracts() throws Exception {
        // Arrange
        Map<String, Object> publicClaims = new LinkedHashMap<>();
        publicClaims.put("vct", "IdentityCredential");
        publicClaims.put("iss", "https://example.com");
        publicClaims.put("cnf", new LinkedHashMap<>(Map.of("jwk", "key")));
        publicClaims.put("sub", "did:example:123");
        publicClaims.put("iat", 1234567890);
        publicClaims.put("exp", 1234567899);
        publicClaims.put("nbf", 1234567880);
        publicClaims.put("jti", "urn:uuid:abc");
        publicClaims.put("aud", "https://verifier.com");
        publicClaims.put("_sd", Arrays.asList("hash1"));
        publicClaims.put("_sd_alg", "sha-256");
        publicClaims.put("id", "did:example:123");
        publicClaims.put("given_name", "John");

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(publicClaims, new LinkedHashMap<>()));

        // Assert
        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        assertTrue(credential.getClaims().contains("$.given_name"));
        assertFalse(credential.getClaims().stream().anyMatch(c ->
                c.contains("vct") || c.contains("iss") || c.contains("cnf") || c.contains("sub") ||
                c.contains("_sd") || c.contains("_sd_alg") || c.contains("id")));
    }

    @Test
    public void testBuildAvailableCredentialWhenSdJwtWithSdClaimsExtractsSdClaimPaths() throws Exception {
        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("family_name", "Doe");
        sdClaims.put("birth_date", "1990-01-01");
        sdClaims.put("credentialSubject.NumberOfCAR", 5);

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), sdClaims));

        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        assertEquals(3, credential.getSdClaims().size());
        assertTrue(credential.getSdClaims().contains("$.family_name"));
        assertTrue(credential.getSdClaims().contains("$.birth_date"));
        assertTrue(credential.getSdClaims().contains("$.NumberOfCAR"));
    }

    @Test
    public void testBuildAvailableCredentialWhenSdJwtWithIssuerConfigExceptionUsesDefaultDisplayName() throws Exception {
        // Arrange
        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), new LinkedHashMap<>()));

        // Assert
        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        assertEquals("Unknown Credential", credential.getCredentialTypeDisplayName());
        assertNull(credential.getCredentialTypeLogo());
    }

    @Test
    public void testCollectPathsWhenMapHasScalarValuesCollectsLeafPaths() throws Exception {
        // Arrange
        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("given_name", "John");
        sdClaims.put("family_name", "Doe");
        sdClaims.put("age", 30);

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), sdClaims));

        // Assert
        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        List<String> paths = credential.getSdClaims();
        assertEquals(3, paths.size());
        assertTrue(paths.containsAll(Arrays.asList("$.given_name", "$.family_name", "$.age")));
    }

    @Test
    public void testExtractSdClaimPathsWhenMapHasNestedMapProducesTopLevelKey() throws Exception {
        Map<String, Object> address = new LinkedHashMap<>();
        address.put("street", "123 Main St");
        address.put("city", "NYC");
        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("address", address);

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), sdClaims));

        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        List<String> paths = credential.getSdClaims();
        assertEquals(1, paths.size());
        assertTrue(paths.contains("$.address"));
    }

    @Test
    public void testExtractSdClaimPathsWhenMapHasSdKeyIncludesSdKey() throws Exception {
        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("name", "John");
        sdClaims.put("_sd", Arrays.asList("hash1", "hash2"));

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), sdClaims));

        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        List<String> paths = credential.getSdClaims();
        assertEquals(2, paths.size());
        assertTrue(paths.contains("$.name"));
        assertTrue(paths.contains("$._sd"));
    }

    @Test
    public void testCollectPathsWhenListHasUniformKeysStopsAtListLevel() throws Exception {
        // Arrange
        Map<String, Object> sdClaims = new LinkedHashMap<>();
        List<Map<String, Object>> genderList = Arrays.asList(
                createMapOf("code", "M", "value", "Male"),
                createMapOf("code", "F", "value", "Female"));
        sdClaims.put("gender", genderList);

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), sdClaims));

        // Assert
        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        List<String> paths = credential.getSdClaims();
        assertTrue(paths.contains("$.gender"));
        assertFalse(paths.contains("$.gender.code"));
        assertFalse(paths.contains("$.gender.value"));
        assertEquals(1, paths.size());
    }

    @Test
    public void testExtractSdClaimPathsWhenListHasSingleMapItemProducesTopLevelKey() throws Exception {
        Map<String, Object> privilege = new LinkedHashMap<>();
        privilege.put("vehicle_category_code", "C");
        privilege.put("issue_date", "2020-01-01");

        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("driving_privileges", Arrays.asList(privilege));

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), sdClaims));

        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        List<String> paths = credential.getSdClaims();
        assertEquals(1, paths.size());
        assertTrue(paths.contains("$.driving_privileges"));
    }

    @Test
    public void testCollectPathsWhenListHasNonMapItemsSkipsNonMapItems() throws Exception {
        // Arrange
        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("tags", Arrays.asList("tag1", "tag2", "tag3"));

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), sdClaims));

        // Assert
        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        List<String> paths = credential.getSdClaims();
        assertEquals(1, paths.size());
        assertTrue(paths.contains("$.tags"));
    }

    @Test
    public void testExtractSdClaimPathsWhenListItemsHaveNoCommonKeysProducesTopLevelKey() throws Exception {
        Map<String, Object> sdClaims = new LinkedHashMap<>();
        List<Map<String, Object>> items = Arrays.asList(
                createMapOf("alpha", 1),
                createMapOf("beta", 2));
        sdClaims.put("mixed", items);

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), sdClaims));

        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        List<String> paths = credential.getSdClaims();
        assertEquals(1, paths.size());
        assertTrue(paths.contains("$.mixed"));
    }

    @Test
    public void testExtractSdClaimPathsComplexDrivingPrivilegesProducesTopLevelKey() throws Exception {
        Map<String, Object> privilege = new LinkedHashMap<>();
        privilege.put("vehicle_category_code", "C");
        privilege.put("issue_date", "2020-01-01");
        privilege.put("expiry_date", "2025-01-01");
        List<Map<String, Object>> codes = Arrays.asList(
                createMapOf("code", "A", "value", "V1"),
                createMapOf("code", "B", "value", "V2"));
        privilege.put("codes", codes);

        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("driving_privileges", List.of(privilege));

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), sdClaims));

        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        List<String> paths = credential.getSdClaims();
        assertEquals(1, paths.size());
        assertTrue(paths.contains("$.driving_privileges"));
    }

    @Test
    public void testExtractSdClaimPathsWhenListContainsMixedTypesProducesTopLevelKey() throws Exception {
        Map<String, Object> sdClaims = new LinkedHashMap<>();
        List<Object> mixedList = new ArrayList<>();
        mixedList.add(createMapOf("key1", "val1"));
        mixedList.add("plain-string");
        mixedList.add(42);
        sdClaims.put("mixed_types", mixedList);

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), sdClaims));

        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        List<String> paths = credential.getSdClaims();
        assertEquals(1, paths.size());
        assertTrue(paths.contains("$.mixed_types"));
    }

    @Test
    public void testCollectPathsWhenEmptyMapProducesNoPaths() throws Exception {
        // Arrange
        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), new LinkedHashMap<>()));

        // Assert
        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        assertTrue(credential.getSdClaims().isEmpty());
        assertTrue(credential.getClaims().isEmpty());
    }

    @Test
    public void testCollectPathsWhenListWithPartiallyOverlappingKeysTreatedAsUniform() throws Exception {
        // Arrange
        Map<String, Object> sdClaims = new LinkedHashMap<>();
        List<Map<String, Object>> codes = Arrays.asList(
                createMapOf("code", "A", "value", "V1", "sign", "+"),
                createMapOf("code", "B", "value", "V2"));
        sdClaims.put("codes", codes);

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), sdClaims));

        // Assert
        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        List<String> paths = credential.getSdClaims();
        assertTrue(paths.contains("$.codes"));
        assertFalse(paths.contains("$.codes.code"));
        assertFalse(paths.contains("$.codes.value"));
        assertFalse(paths.contains("$.codes.sign"));
        assertEquals(1, paths.size());
    }

    @Test
    public void testCollectPathsWhenEmptyListProducesPathButNoRecursion() throws Exception {
        // Arrange
        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("empty_list", new ArrayList<>());

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), sdClaims));

        // Assert
        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        List<String> paths = credential.getSdClaims();
        assertEquals(1, paths.size());
        assertTrue(paths.contains("$.empty_list"));
    }

    @Test
    public void testExtractSdClaimPathsWhenDeeplyNestedMapsProducesTopLevelKey() throws Exception {
        Map<String, Object> level3 = new LinkedHashMap<>();
        level3.put("deep_value", "found");
        Map<String, Object> level2 = new LinkedHashMap<>();
        level2.put("level3", level3);
        Map<String, Object> level1 = new LinkedHashMap<>();
        level1.put("level2", level2);
        Map<String, Object> sdClaims = new LinkedHashMap<>();
        sdClaims.put("level1", level1);

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), sdClaims));

        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        List<String> paths = credential.getSdClaims();
        assertEquals(1, paths.size());
        assertTrue(paths.contains("$.level1"));
    }

  
    @Test
    public void testMatchesFormatWhenLdpVcProofTypeNullCredentialNotSelected() throws Exception {
        // Arrange
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        Map<String, List<String>> ldpVcFormat = new HashMap<>();
        ldpVcFormat.put("proof_type", Arrays.asList("Ed25519Signature2020"));
        format.put("ldp_vc", ldpVcFormat);

        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, format, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        VCCredentialProperties propsWithNullProof = new VCCredentialProperties();
        propsWithNullProof.setType(Arrays.asList("VerifiableCredential"));
        propsWithNullProof.setProof(null);
        doReturn(propsWithNullProof).when(objectMapper).convertValue(any(), eq(VCCredentialProperties.class));

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testMatchesFormatWhenLdpVcProofTypeListEmptyCredentialSelected() throws Exception {
        // Arrange
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        Map<String, List<String>> ldpVcFormat = new HashMap<>();
        ldpVcFormat.put("proof_type", Collections.emptyList());
        format.put("ldp_vc", ldpVcFormat);

        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, format, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        VCCredentialProperties props = new VCCredentialProperties();
        props.setType(Arrays.asList("VerifiableCredential"));
        doReturn(props).when(objectMapper).convertValue(any(), eq(VCCredentialProperties.class));

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testMatchesFormatWhenLdpVcRequiredProofTypesNullCredentialSelected() throws Exception {
        // Arrange
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        Map<String, List<String>> ldpVcFormat = new HashMap<>();
        ldpVcFormat.put("proof_type", null);
        format.put("ldp_vc", ldpVcFormat);

        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, format, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        VCCredentialProperties props = new VCCredentialProperties();
        props.setType(Arrays.asList("VerifiableCredential"));
        doReturn(props).when(objectMapper).convertValue(any(), eq(VCCredentialProperties.class));

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testMatchesFormatWhenLdpVcNullLdpVcFormatCredentialSelected() throws Exception {
        // Arrange
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        format.put("ldp_vc", null);

        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, format, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testMatchesFormatWhenLdpVcProofTypeMismatchCredentialNotSelected() throws Exception {
        // Arrange
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        Map<String, List<String>> ldpVcFormat = new HashMap<>();
        ldpVcFormat.put("proof_type", Arrays.asList("Ed25519Signature2020"));
        format.put("ldp_vc", ldpVcFormat);

        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, format, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMatchingFormat());

        VCCredentialProperties propsWithWrongProof = new VCCredentialProperties();
        propsWithWrongProof.setType(Arrays.asList("VerifiableCredential"));
        VCCredentialResponseProof wrongProof = new VCCredentialResponseProof();
        wrongProof.setType("EcdsaSecp256k1Signature2019");
        propsWithWrongProof.setProof(wrongProof);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(propsWithWrongProof);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testMatchesFormatWhenLdpVcCredentialAndDescriptorLacksLdpVcKeyCredentialNotSelected() throws Exception {
        // Arrange
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        format.put(CredentialFormat.VC_SD_JWT.getFormat(), new HashMap<>());

        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, format, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

   
    @Test
    public void testEvaluateJsonPathWhenPathDoesNotStartWithDollarDotNoMatch() throws Exception {
        // Arrange
        Fields field = new Fields(Arrays.asList("type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testEvaluateJsonPathWhenJsonPathValueIsNullNoMatch() throws Exception {
        // Arrange
        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("name", null);
        credentialData.put("type", Arrays.asList("VerifiableCredential"));

        Fields field = new Fields(Arrays.asList("$.name"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithSampleData(credentialData));

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testEvaluateJsonPathWhenResultIsSingleValueWrapsInList() throws Exception {
        // Arrange
        Fields nameField = new Fields(Arrays.asList("$.name"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(nameField), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithSimpleFilterData());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

   
    @Test
    public void testExtractClaimsFromFieldsWhenFieldsContainNullSkipsNullFields() throws Exception {
        // Arrange
        List<Fields> fieldsList = new ArrayList<>();
        fieldsList.add(null);
        fieldsList.add(new Fields(Arrays.asList("$.type"), null, null, null, null, null));
        Constraints constraints = new Constraints(fieldsList, null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Collections.emptyList());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
        assertTrue(result.getMatchingCredentialsResponse().getMissingClaims().contains("test"));
    }

    @Test
    public void testExtractClaimsFromFieldsWhenFieldsIsNullReturnsEmptyList() throws Exception {
        // Arrange
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        format.put(CredentialFormat.VC_SD_JWT.getFormat(), new HashMap<>());

        Constraints constraints = new Constraints(null, null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, format, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
        assertTrue(result.getMatchingCredentialsResponse().getMissingClaims().contains("sd-jwt_alg_values"));
    }

    @Test
    public void testExtractRequiredClaimsWhenDeduplicateEnabledRemovesDuplicates() throws Exception {
        // Arrange
        Fields field1 = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints1 = new Constraints(Collections.singletonList(field1), null);
        InputDescriptor desc1 = new InputDescriptor("desc-1", null, null, null, constraints1);

        Fields field2 = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints2 = new Constraints(Collections.singletonList(field2), null);
        InputDescriptor desc2 = new InputDescriptor("desc-2", null, null, null, constraints2);

        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(desc1, desc2), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Collections.emptyList());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertEquals(2, result.getMatchingCredentialsResponse().getMissingClaims().size());
        assertTrue(result.getMatchingCredentialsResponse().getMissingClaims().contains("desc-1"));
        assertTrue(result.getMatchingCredentialsResponse().getMissingClaims().contains("desc-2"));
    }


    @Test
    public void testExtractSdJwtAlgorithmWhenSdJwtStringIsNullReturnsNull() throws Exception {
        // Arrange
        Method method = CredentialMatchingServiceImpl.class.getDeclaredMethod("extractSdJwtAlgorithm", String.class);
        method.setAccessible(true);

        // Act
        String result = (String) method.invoke(credentialMatchingService, (String) null);

        // Assert
        assertNull(result);
    }

    @Test
    public void testMatchesConstraintsWhenFieldsAreNullReturnsTrue() throws Exception {
        // Arrange
        Method method = CredentialMatchingServiceImpl.class.getDeclaredMethod(
                "matchesConstraints", VCCredentialResponse.class, Constraints.class);
        method.setAccessible(true);

        VCCredentialResponse vc = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(new HashMap<>())
                .build();
        Constraints constraints = new Constraints(null, null);

        // Act
        boolean result = (boolean) method.invoke(credentialMatchingService, vc, constraints);

        // Assert
        assertTrue(result);
    }

    @Test
    public void testEvaluateJsonPathWhenPathIsNullReturnsEmptyList() throws Exception {
        // Arrange
        Fields field = new Fields(Collections.singletonList(null), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testEvaluateJsonPathWhenJsonIsNullReturnsEmptyList() throws Exception {
        // Arrange
        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());
        when(credentialFormatHandler.extractAllCredentialProperties(any(VCCredentialResponse.class)))
                .thenReturn(null);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testMatchesFieldPathWhenPathNotFoundInCredentialReturnsFalse() throws Exception {
        // Arrange
        Method method = CredentialMatchingServiceImpl.class.getDeclaredMethod(
                "matchesFieldPath", VCCredentialResponse.class, String.class, Filter.class);
        method.setAccessible(true);

        VCCredentialResponse vc = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(new HashMap<>())
                .build();

        // Act
        boolean result = (boolean) method.invoke(credentialMatchingService, vc, "$.nonexistent", null);

        // Assert
        assertFalse(result);
    }

    @Test
    public void testExtractRequiredClaimsWhenDescriptorHasNullFieldsFilteredOut() throws Exception {
        // Arrange
        Constraints constraintsWithNullFields = new Constraints(null, null);
        InputDescriptor descNullFields = new InputDescriptor("desc-null", null, null, null, constraintsWithNullFields);

        Fields field = new Fields(Arrays.asList("$.name"), null, null, null, null, null);
        Constraints constraintsWithFields = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descWithFields = new InputDescriptor("desc-valid", null, null, null, constraintsWithFields);

        PresentationDefinition pd = new PresentationDefinition(
                "test-pd", Arrays.asList(descNullFields, descWithFields), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Collections.emptyList());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertEquals(2, result.getMatchingCredentialsResponse().getMissingClaims().size());
        assertTrue(result.getMatchingCredentialsResponse().getMissingClaims().contains("desc-null"));
        assertTrue(result.getMatchingCredentialsResponse().getMissingClaims().contains("desc-valid"));
    }

    @Test
    public void testExtractClaimKeyFromPathWhenTailStartsWithDollarStrippsDollarPrefix() throws Exception {
        // Arrange
        Fields field = new Fields(Arrays.asList("$.$id"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Collections.emptyList());

        // Act
        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertTrue(result.getMatchingCredentialsResponse().getMissingClaims().contains("test"));
    }

    @Test
    public void testExtractSdClaimPathsWhenListHasMapsAndNonMapsProducesTopLevelKey() throws Exception {
        Map<String, Object> sdClaims = new LinkedHashMap<>();
        List<Object> mixedList = new ArrayList<>();
        mixedList.add(createMapOf("code", "A", "value", "V1"));
        mixedList.add(createMapOf("code", "B", "value", "V2"));
        mixedList.add("not-a-map");
        sdClaims.put("data", mixedList);

        MatchingCredentialsDTO result = executeSdJwtNoConstraintFlow(
                createSdJwtAllClaimsMap(new LinkedHashMap<>(), sdClaims));

        CredentialDTO credential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        List<String> paths = credential.getSdClaims();
        assertEquals(1, paths.size());
        assertTrue(paths.contains("$.data"));
    }

    private static final String SD_JWT_HS256 =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.sig";

    private static final String SD_JWT_NO_ALG =
            "eyJ0eXAiOiJKV1QifQ.eyJpc3MiOiJ0ZXN0In0.sig";

    private static final String SD_JWT_NON_STRING_ALG =
            "eyJhbGciOjEyM30.eyJpc3MiOiJ0ZXN0In0.sig";

    private PresentationDefinition createSdJwtPresentationDefinition(List<String> algorithmValues) {
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        Map<String, List<String>> sdJwtFormat = new HashMap<>();
        sdJwtFormat.put("sd-jwt_alg_values", algorithmValues);
        format.put(CredentialFormat.VC_SD_JWT.getFormat(), sdJwtFormat);

        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("sd-jwt-descriptor", null, null, format, constraints);
        return new PresentationDefinition("sd-jwt-pd", Arrays.asList(descriptor), null, null, null);
    }

    private DecryptedCredentialDTO createDecryptedSdJwtCredential(Object credentialPayload) {
        DecryptedCredentialDTO credential = new DecryptedCredentialDTO();
        credential.setId("sd-jwt-credential-id");
        credential.setWalletId(walletId);

        VCCredentialResponse response = VCCredentialResponse.builder()
                .format(CredentialFormat.VC_SD_JWT.getFormat())
                .credential(credentialPayload)
                .build();
        credential.setCredential(response);

        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("test-issuer-id");
        metadata.setCredentialType("TestCredential");
        credential.setCredentialMetadata(metadata);
        credential.setCreatedAt(Instant.now());
        credential.setUpdatedAt(Instant.now());

        return credential;
    }

    private void setupSdJwtHandlerMock(Map<String, Object> publicClaims, Map<String, Object> sdClaims) {
        setupSdJwtHandlerMock(publicClaims, sdClaims, null);
    }

    private void setupSdJwtHandlerMock(Map<String, Object> publicClaims, Map<String, Object> sdClaims,
                                       Map<String, Object> sdClaimValues) {
        when(credentialFormatHandler.extractAllCredentialProperties(any(VCCredentialResponse.class)))
                .thenAnswer(invocation -> {
                    VCCredentialResponse vc = invocation.getArgument(0);
                    String format = vc.getFormat();

                    if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(format)
                            || CredentialFormat.DC_SD_JWT.getFormat().equalsIgnoreCase(format)) {
                        Map<String, Map<String, Object>> result = new LinkedHashMap<>();
                        result.put("publicClaims", new LinkedHashMap<>(publicClaims));
                        result.put("sdClaims", new LinkedHashMap<>(sdClaims));
                        if (sdClaimValues != null) {
                            result.put("sdClaimValues", new LinkedHashMap<>(sdClaimValues));
                        }
                        return result;
                    }
                    Object cred = vc.getCredential();
                    if (cred instanceof Map) {
                        return new LinkedHashMap<>((Map<?, ?>) cred);
                    }
                    return new LinkedHashMap<>();
                });
    }

    private MatchingCredentialsDTO executeSdJwtNoConstraintFlow(
            Map<String, Map<String, Object>> handlerReturn) throws Exception {
        Constraints constraints = new Constraints(null, null);
        InputDescriptor descriptor = new InputDescriptor("sd-jwt-test", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("sd-jwt-pd",
                Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Arrays.asList(createDecryptedSdJwtCredential(SD_JWT_HS256)));
        when(credentialFormatHandler.extractAllCredentialProperties(any(VCCredentialResponse.class)))
                .thenAnswer(invocation -> handlerReturn);

        return credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);
    }

    private Map<String, Map<String, Object>> createSdJwtAllClaimsMap(
            Map<String, Object> publicClaims, Map<String, Object> sdClaims) {
        return createSdJwtAllClaimsMap(publicClaims, sdClaims, null);
    }

    private Map<String, Map<String, Object>> createSdJwtAllClaimsMap(
            Map<String, Object> publicClaims, Map<String, Object> sdClaims, Map<String, Object> sdClaimValues) {
        Map<String, Map<String, Object>> allClaims = new LinkedHashMap<>();
        allClaims.put("publicClaims",
                publicClaims != null ? new LinkedHashMap<>(publicClaims) : null);
        allClaims.put("sdClaims",
                sdClaims != null ? new LinkedHashMap<>(sdClaims) : null);
        if (sdClaimValues != null) {
            allClaims.put("sdClaimValues", new LinkedHashMap<>(sdClaimValues));
        }
        return allClaims;
    }

    private Map<String, Object> createMapOf(Object... keyValues) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            map.put((String) keyValues[i], keyValues[i + 1]);
        }
        return map;
    }

    // --- extractFormatConstraintKeys ---

    @Test
    public void testExtractFormatConstraintKeysWhenVcSdJwtFormatReturnsSdJwtAlgValues() throws Exception {
        Method method = CredentialMatchingServiceImpl.class.getDeclaredMethod("extractFormatConstraintKeys", InputDescriptor.class);
        method.setAccessible(true);

        Map<String, Map<String, List<String>>> format = new HashMap<>();
        format.put(CredentialFormat.VC_SD_JWT.getFormat(), new HashMap<>());
        InputDescriptor descriptor = new InputDescriptor("test-id", null, null, format, new Constraints(null, null));

        @SuppressWarnings("unchecked")
        Set<String> result = (Set<String>) method.invoke(credentialMatchingService, descriptor);
        assertEquals(1, result.size());
        assertTrue(result.contains("sd-jwt_alg_values"));
    }

    @Test
    public void testExtractFormatConstraintKeysWhenLdpVcFormatReturnsProofType() throws Exception {
        Method method = CredentialMatchingServiceImpl.class.getDeclaredMethod("extractFormatConstraintKeys", InputDescriptor.class);
        method.setAccessible(true);

        Map<String, Map<String, List<String>>> format = new HashMap<>();
        format.put("ldp_vc", new HashMap<>());
        InputDescriptor descriptor = new InputDescriptor("test-id", null, null, format, new Constraints(null, null));

        @SuppressWarnings("unchecked")
        Set<String> result = (Set<String>) method.invoke(credentialMatchingService, descriptor);
        assertEquals(1, result.size());
        assertTrue(result.contains("proof_type"));
    }

    @Test
    public void testExtractFormatConstraintKeysWhenNullFormatReturnsDescriptorId() throws Exception {
        Method method = CredentialMatchingServiceImpl.class.getDeclaredMethod("extractFormatConstraintKeys", InputDescriptor.class);
        method.setAccessible(true);

        InputDescriptor descriptor = new InputDescriptor("my-descriptor-id", null, null, null, new Constraints(null, null));

        @SuppressWarnings("unchecked")
        Set<String> result = (Set<String>) method.invoke(credentialMatchingService, descriptor);
        assertEquals(1, result.size());
        assertTrue(result.contains("my-descriptor-id"));
    }

    @Test
    public void testExtractFormatConstraintKeysWhenBothFormatsPresentReturnsBothKeys() throws Exception {
        Method method = CredentialMatchingServiceImpl.class.getDeclaredMethod("extractFormatConstraintKeys", InputDescriptor.class);
        method.setAccessible(true);

        Map<String, Map<String, List<String>>> format = new HashMap<>();
        format.put(CredentialFormat.VC_SD_JWT.getFormat(), new HashMap<>());
        format.put("ldp_vc", new HashMap<>());
        InputDescriptor descriptor = new InputDescriptor("test-id", null, null, format, new Constraints(null, null));

        @SuppressWarnings("unchecked")
        Set<String> result = (Set<String>) method.invoke(credentialMatchingService, descriptor);
        assertEquals(2, result.size());
        assertTrue(result.contains("sd-jwt_alg_values"));
        assertTrue(result.contains("proof_type"));
    }

    // --- getMatchingCredentials else-block: hasFormatMatch paths ---

    @Test
    public void testGetMatchingCredentialsWhenFormatMatchesButConstraintFailsUsesMissingFieldNames() throws Exception {
        // Descriptor: ldp_vc with empty proof_type list + $.name constraint
        // Wallet: ldp_vc credential that passes matchesFormat but not matchesConstraints
        // Expected: missingClaims = ["name"] (field names), not "proof_type" (format key)
        Map<String, List<String>> ldpVcFormatMap = new HashMap<>();
        ldpVcFormatMap.put("proof_type", Collections.emptyList());
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        format.put("ldp_vc", ldpVcFormatMap);

        Fields nameField = new Fields(Arrays.asList("$.name"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(nameField), null);
        InputDescriptor descriptor = new InputDescriptor("ldp-desc", null, null, format, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        // ldp_vc credential without a top-level "name" field → constraint fails
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        VCCredentialProperties props = new VCCredentialProperties();
        doReturn(props).when(objectMapper).convertValue(any(), eq(VCCredentialProperties.class));

        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
        assertTrue("field name must appear when format matched",
                result.getMatchingCredentialsResponse().getMissingClaims().contains("name"));
        assertFalse("format key must NOT appear when format matched",
                result.getMatchingCredentialsResponse().getMissingClaims().contains("proof_type"));
    }

    @Test
    public void testGetMatchingCredentialsWhenNoFormatMatchReturnsSdJwtAlgValuesKey() throws Exception {
        // Descriptor: vc+sd-jwt format; wallet has only ldp_vc credential
        // Expected: missingClaims = ["sd-jwt_alg_values"] (format key), not constraint field names
        Map<String, List<String>> sdJwtFormatMap = new HashMap<>();
        sdJwtFormatMap.put("sd-jwt_alg_values", Arrays.asList("ES256"));
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        format.put(CredentialFormat.VC_SD_JWT.getFormat(), sdJwtFormatMap);

        Fields vctField = new Fields(Arrays.asList("$.vct"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(vctField), null);
        InputDescriptor descriptor = new InputDescriptor("sdjwt-desc", null, null, format, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean())).thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData()); // ldp_vc credential only

        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);

        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
        assertTrue("format key must appear when no format match",
                result.getMatchingCredentialsResponse().getMissingClaims().contains("sd-jwt_alg_values"));
        assertFalse("field name must NOT appear when no format match",
                result.getMatchingCredentialsResponse().getMissingClaims().contains("vct"));
    }

    // --- DCQL matching (matchWithDcqlQuery) ---

    @Test
    public void testGetMatchingCredentialsDcqlSuccessWithLdpVcMatch() throws Exception {
        VerifiablePresentationSessionData dcqlSession = createDcqlSessionData();
        CredentialQuery credentialQuery = mock(CredentialQuery.class);
        when(credentialQuery.getId()).thenReturn("identity-query");
        when(credentialQuery.getFormat()).thenReturn(CredentialFormat.LDP_VC.getFormat());
        when(credentialQuery.getMultiple()).thenReturn(false);
        when(credentialQuery.getClaims()).thenReturn(null);
        stubCredentialQueryBasics(credentialQuery);

        DCQLQuery dcqlQuery = mock(DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(credentialQuery));
        when(dcqlQuery.getCredentialSets()).thenReturn(null);
        stubDcqlQuery(dcqlQuery);

        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(createMockIssuerConfig());

        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(
                dcqlSession, walletId, base64Key);

        assertNotNull(result.getMatchingCredentialsResponse().getQueryGroups());
        assertEquals(1, result.getMatchingCredentialsResponse().getQueryGroups().size());
        DcqlQueryGroup group = result.getMatchingCredentialsResponse().getQueryGroups().get(0);
        assertEquals("identity-query", group.getQueryId());
        assertFalse(group.getAvailableCredentials().isEmpty());
        assertTrue(group.getMissingClaims().isEmpty());
        assertNull(group.getAvailableCredentials().get(0).getClaims());
        assertEquals(1, result.getMatchingCredentials().size());
        assertEquals("identity-query", result.getMatchingCredentials().get(0).getIdentifier());
        verify(openID4VPService).resolveDcqlQuery(anyString(), anyString(), anyBoolean());
        verify(openID4VPService, never()).resolvePresentationDefinition(any(), any(), anyBoolean());
    }

    @Test
    public void testGetMatchingCredentialsDcqlNullWalletId() throws Exception {
        VerifiablePresentationSessionData dcqlSession = createDcqlSessionData();
        stubDcqlQuery(mock(DCQLQuery.class));

        try {
            credentialMatchingService.getMatchingCredentials(dcqlSession, null, base64Key);
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertEquals("Wallet ID cannot be null or empty", e.getMessage());
        }
    }

    @Test
    public void testGetMatchingCredentialsDcqlEmptyWalletId() throws Exception {
        VerifiablePresentationSessionData dcqlSession = createDcqlSessionData();
        stubDcqlQuery(mock(DCQLQuery.class));

        try {
            credentialMatchingService.getMatchingCredentials(dcqlSession, "   ", base64Key);
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertEquals("Wallet ID cannot be null or empty", e.getMessage());
        }
    }

    @Test
    public void testGetMatchingCredentialsDcqlWhenResolveReturnsNull() throws Exception {
        VerifiablePresentationSessionData dcqlSession = createDcqlSessionData();
        when(openID4VPService.resolveDcqlQuery(anyString(), anyString(), anyBoolean())).thenReturn(null);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        try {
            credentialMatchingService.getMatchingCredentials(dcqlSession, walletId, base64Key);
            fail("Expected InvalidRequestException");
        } catch (InvalidRequestException e) {
            assertTrue(e.getMessage().contains("Authorization request does not contain a DCQL query"));
        }
    }

    @Test
    public void testGetMatchingCredentialsDcqlNoFormatMatchReturnsMissingClaims() throws Exception {
        VerifiablePresentationSessionData dcqlSession = createDcqlSessionData();
        CredentialQuery credentialQuery = mock(CredentialQuery.class);
        when(credentialQuery.getId()).thenReturn("sdjwt-query");
        when(credentialQuery.getFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        when(credentialQuery.getMultiple()).thenReturn(false);
        when(credentialQuery.getClaims()).thenReturn(null);
        stubCredentialQueryBasics(credentialQuery);

        DCQLQuery dcqlQuery = mock(DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(credentialQuery));
        when(dcqlQuery.getCredentialSets()).thenReturn(null);
        stubDcqlQuery(dcqlQuery);

        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(
                dcqlSession, walletId, base64Key);

        DcqlQueryGroup group = result.getMatchingCredentialsResponse().getQueryGroups().get(0);
        assertTrue(group.getAvailableCredentials().isEmpty());
        assertTrue(result.getMatchingCredentials().isEmpty());
    }

    @Test
    public void testGetMatchingCredentialsDcqlIncludesCredentialSets() throws Exception {
        VerifiablePresentationSessionData dcqlSession = createDcqlSessionData();
        CredentialQuery credentialQuery = mock(CredentialQuery.class);
        when(credentialQuery.getId()).thenReturn("pan");
        when(credentialQuery.getFormat()).thenReturn(CredentialFormat.LDP_VC.getFormat());
        when(credentialQuery.getMultiple()).thenReturn(false);
        when(credentialQuery.getClaims()).thenReturn(null);
        stubCredentialQueryBasics(credentialQuery);

        CredentialSetQuery setQuery = mock(CredentialSetQuery.class);
        when(setQuery.getRequired()).thenReturn(true);
        when(setQuery.getOptions()).thenReturn(List.of(List.of("pan"), List.of("aadhaar")));

        DCQLQuery dcqlQuery = mock(DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(credentialQuery));
        when(dcqlQuery.getCredentialSets()).thenReturn(List.of(setQuery));
        stubDcqlQuery(dcqlQuery);

        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(createMockIssuerConfig());

        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(
                dcqlSession, walletId, base64Key);

        assertEquals(1, result.getMatchingCredentialsResponse().getCredentialSets().size());
        CredentialSetInfo credentialSet = result.getMatchingCredentialsResponse().getCredentialSets().get(0);
        assertTrue(credentialSet.isRequired());
        assertEquals(List.of(List.of("pan"), List.of("aadhaar")), credentialSet.getOptions());
    }

    @Test
    public void testGetMatchingCredentialsDcqlSynthesizesCredentialSetsWhenAbsent() throws Exception {
        VerifiablePresentationSessionData dcqlSession = createDcqlSessionData();
        CredentialQuery governmentIdentity = new CredentialQuery(
                "government-identity", CredentialFormat.DC_SD_JWT.getFormat(), false,
                Map.of(), false, null, null);
        CredentialQuery ageProof = new CredentialQuery(
                "age-proof", CredentialFormat.DC_SD_JWT.getFormat(), false,
                Map.of(), false, null, null);

        DCQLQuery dcqlQuery = mock(DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(governmentIdentity, ageProof));
        when(dcqlQuery.getCredentialSets()).thenReturn(null);
        stubDcqlQuery(dcqlQuery);

        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(
                dcqlSession, walletId, base64Key);

        List<CredentialSetInfo> credentialSets = result.getMatchingCredentialsResponse().getCredentialSets();
        assertEquals(2, credentialSets.size());
        assertTrue(credentialSets.get(0).isRequired());
        assertEquals(List.of(List.of("government-identity")), credentialSets.get(0).getOptions());
        assertTrue(credentialSets.get(1).isRequired());
        assertEquals(List.of(List.of("age-proof")), credentialSets.get(1).getOptions());
    }

    @Test
    public void testGetMatchingCredentialsDcqlMatchesWithClaimPath() throws Exception {
        VerifiablePresentationSessionData dcqlSession = createDcqlSessionData();
        ClaimsQuery nameClaim = new ClaimsQuery(
                "name-claim", List.of("credentialSubject", "name"), null);
        CredentialQuery credentialQuery = new CredentialQuery(
                "identity-query", CredentialFormat.LDP_VC.getFormat(), false,
                Map.of(), false, List.of(nameClaim), null);

        DCQLQuery dcqlQuery = mock(DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(credentialQuery));
        when(dcqlQuery.getCredentialSets()).thenReturn(null);
        stubDcqlQuery(dcqlQuery);

        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(createMockIssuerConfig());

        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(
                dcqlSession, walletId, base64Key);

        assertFalse(result.getMatchingCredentialsResponse().getQueryGroups().get(0).getAvailableCredentials().isEmpty());
        assertTrue(result.getMatchingCredentials().size() == 1);
    }

    @Test
    public void testGetMatchingCredentialsDcqlNoMatchWithClaimSetsReturnsMissingClaimPaths() throws Exception {
        VerifiablePresentationSessionData dcqlSession = createDcqlSessionData();
        ClaimsQuery ageClaim = new ClaimsQuery(
                "age-above-18", List.of("age_above_18"),
                List.of(new ClaimValue.BoolValue(true)));
        ClaimsQuery dobClaim = new ClaimsQuery(
                "date-of-birth", List.of("dateOfBirth"), null);
        CredentialQuery credentialQuery = new CredentialQuery(
                "age-proof", CredentialFormat.DC_SD_JWT.getFormat(), false,
                Map.of(), false, List.of(ageClaim, dobClaim),
                List.of(List.of("age-above-18"), List.of("date-of-birth")));

        DCQLQuery dcqlQuery = mock(DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(credentialQuery));
        when(dcqlQuery.getCredentialSets()).thenReturn(null);
        stubDcqlQuery(dcqlQuery);

        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithMapData());

        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(
                dcqlSession, walletId, base64Key);

        DcqlQueryGroup group = result.getMatchingCredentialsResponse().getQueryGroups().get(0);
        assertTrue(group.getAvailableCredentials().isEmpty());
        assertTrue(group.getMissingClaims().contains("$.age_above_18"));
        assertTrue(group.getMissingClaims().contains("$.dateOfBirth"));
    }

    @Test
    public void testGetMatchingCredentialsDcqlMatchesSdJwtClaimValueWithDecodedDisclosures() throws Exception {
        VerifiablePresentationSessionData dcqlSession = createDcqlSessionData();
        ClaimsQuery ageClaim = new ClaimsQuery(
                "age-above-18", List.of("age_above_18"),
                List.of(new ClaimValue.BoolValue(true)));
        CredentialQuery credentialQuery = new CredentialQuery(
                "age-proof", CredentialFormat.DC_SD_JWT.getFormat(), false,
                Map.of(), false, List.of(ageClaim), null);

        DCQLQuery dcqlQuery = mock(DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(credentialQuery));
        when(dcqlQuery.getCredentialSets()).thenReturn(null);
        stubDcqlQuery(dcqlQuery);

        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithDcSdJwtToken(true));
        when(credentialFormatHandlerFactory.getHandler(CredentialFormat.DC_SD_JWT.getFormat()))
                .thenReturn(credentialFormatHandler);
        setupSdJwtHandlerMock(
                Map.of("age_above_18", true),
                Collections.emptyMap(),
                Collections.emptyMap());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(createMockIssuerConfig());

        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(
                dcqlSession, walletId, base64Key);

        DcqlQueryGroup group = result.getMatchingCredentialsResponse().getQueryGroups().get(0);
        assertFalse(group.getAvailableCredentials().isEmpty());
        assertTrue(group.getMissingClaims().isEmpty());
    }

    @Test
    public void testGetMatchingCredentialsDcqlSdJwtFormatAliasMatch() throws Exception {
        VerifiablePresentationSessionData dcqlSession = createDcqlSessionData();
        CredentialQuery credentialQuery = mock(CredentialQuery.class);
        when(credentialQuery.getId()).thenReturn("sdjwt-query");
        when(credentialQuery.getFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        when(credentialQuery.getMultiple()).thenReturn(false);
        when(credentialQuery.getClaims()).thenReturn(null);
        stubCredentialQueryBasics(credentialQuery);

        DCQLQuery dcqlQuery = mock(DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(credentialQuery));
        when(dcqlQuery.getCredentialSets()).thenReturn(null);
        stubDcqlQuery(dcqlQuery);

        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithSdJwtFormat());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(createMockIssuerConfig());

        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(
                dcqlSession, walletId, base64Key);

        assertFalse(result.getMatchingCredentialsResponse().getQueryGroups().get(0).getAvailableCredentials().isEmpty());
        assertEquals(1, result.getMatchingCredentials().size());
    }

    @Test
    public void testGetMatchingCredentialsDcqlRejectsSdJwtWithoutHolderBindingWhenRequired() throws Exception {
        VerifiablePresentationSessionData dcqlSession = createDcqlSessionData();
        CredentialQuery credentialQuery = new CredentialQuery(
                "bound-card",
                CredentialFormat.VC_SD_JWT.getFormat(),
                false,
                Map.of("vct_values", List.of("https://example.com/employee")),
                true,
                null,
                null);

        DCQLQuery dcqlQuery = mock(DCQLQuery.class);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(credentialQuery));
        when(dcqlQuery.getCredentialSets()).thenReturn(null);
        stubDcqlQuery(dcqlQuery);

        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithSdJwtFormat());

        MatchingCredentialsDTO result = credentialMatchingService.getMatchingCredentials(
                dcqlSession, walletId, base64Key);

        DcqlQueryGroup group = result.getMatchingCredentialsResponse().getQueryGroups().get(0);
        assertTrue(group.getAvailableCredentials().isEmpty());
        assertTrue(result.getMatchingCredentials().isEmpty());
    }

    private VerifiablePresentationSessionData createDcqlSessionData() {
        VerifiablePresentationSessionData data = new VerifiablePresentationSessionData();
        data.setPresentationId("presentation-123");
        data.setAuthorizationRequest("client_id=test-client&response_type=vp_token");
        data.setCreatedAt(Instant.parse("2025-09-08T12:34:56Z"));
        data.setVerifierClientPreregistered(true);
        data.setSpecVersion(SpecVersion.V1);
        return data;
    }

    private void stubDcqlQuery(DCQLQuery dcqlQuery) throws Exception {
        when(openID4VPService.resolveDcqlQuery(anyString(), anyString(), anyBoolean()))
                .thenReturn(dcqlQuery);
    }

    private void stubCredentialQueryBasics(CredentialQuery credentialQuery) {
        when(credentialQuery.getMeta()).thenReturn(Map.of());
        when(credentialQuery.getRequireCryptographicHolderBinding()).thenReturn(false);
    }

    private List<DecryptedCredentialDTO> createMockWalletCredentialsWithDcSdJwtToken(boolean includeAgeClaim)
            throws Exception {
        Map<String, Object> payload = new HashMap<>();
        payload.put("vct", "https://example.com/age");
        payload.put("cnf", Map.of("kid", "key-1"));
        if (includeAgeClaim) {
            payload.put("age_above_18", true);
        }

        DecryptedCredentialDTO credential = new DecryptedCredentialDTO();
        credential.setId("test-credential-id");
        credential.setWalletId(walletId);

        VCCredentialResponse response = VCCredentialResponse.builder()
                .format(CredentialFormat.DC_SD_JWT.getFormat())
                .credential(buildTestSdJwtToken(payload))
                .build();

        credential.setCredential(response);

        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("test-issuer-id");
        metadata.setCredentialType("TestCredential");
        credential.setCredentialMetadata(metadata);
        credential.setCreatedAt(Instant.now());
        credential.setUpdatedAt(Instant.now());

        return List.of(credential);
    }

    private String buildTestSdJwtToken(Map<String, Object> payload) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString(mapper.writeValueAsBytes(Map.of("alg", "none")));
        String encodedPayload = encoder.encodeToString(mapper.writeValueAsBytes(payload));
        return header + "." + encodedPayload + ".signature";
    }
}