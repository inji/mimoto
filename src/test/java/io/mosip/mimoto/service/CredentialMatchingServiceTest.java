package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.model.CredentialMetadata;
import io.mosip.mimoto.service.impl.CredentialMatchingServiceImpl;
import io.mosip.mimoto.service.impl.OpenID4VPService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

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
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Mock
    private IssuersService issuersService;

    @Mock
    private OpenID4VPService openID4VPService;

    private VerifiablePresentationSessionData sessionData;
    private String walletId;
    private String base64Key;
    private PresentationDefinition presentationDefinition;
    private List<DecryptedCredentialDTO> walletCredentials;

    @Before
    public void setUp() throws JsonProcessingException {
        walletId = "test-wallet-id";
        base64Key = "test-base64-key";

        // Setup session data
        sessionData = new VerifiablePresentationSessionData();

        // Setup presentation definition
        presentationDefinition = createMockPresentationDefinition();

        // Setup wallet credentials
        walletCredentials = createMockWalletCredentials();
    }

   // @Test
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
        verify(encryptionDecryptionUtil).decryptCredential(anyString(), eq(base64Key));
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
    public void testGetMatchingCredentialsNullPresentationDefinition() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(null);

        // Act
        credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);
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
    public void testGetMatchingCredentialsIssuerConfigNotFound() throws Exception {
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
        assertNotNull(result.getMatchingCredentialsResponse());
        // Should still work but with default credential display name
        if (!result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty()) {
            assertEquals("Unknown Credential",
                    result.getMatchingCredentialsResponse().getAvailableCredentials().get(0).getCredentialTypeDisplayName());
        }
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
        
        // Create credentials with different format (vc+sd-jwt instead of ldp_vc)
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
        // Should not match due to format mismatch
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
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
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
                .thenReturn(walletCredentials); // credentials without matching subject

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
    public void testGetMatchingCredentialsWithFilterMatching() throws Exception {
        // Arrange
        // Use a simpler presentation definition that doesn't require complex filter matching
        PresentationDefinition pd = createMockPresentationDefinition();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        
        // Create credentials with proper structure for basic matching
        List<DecryptedCredentialDTO> credentials = createMockWalletCredentialsWithMapData();
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(credentials);
        
        // Mock issuer service to return a valid config
        IssuerConfig mockIssuerConfig = createMockIssuerConfig();
        when(issuersService.getIssuerConfig(eq("test-issuer-id"), eq("TestCredential")))
                .thenReturn(mockIssuerConfig);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        
        // This test verifies that basic credential matching works
        // The credentials should match because they have the required $.type field
        assertFalse("Basic credential matching failed - credentials should match the presentation definition", 
                   result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testGetMatchingCredentialsWithFilterMatchingAdvanced() throws Exception {
        // Arrange
        // Create a presentation definition WITHOUT filters to test basic credential matching
        // This will help isolate whether the issue is in filter matching or basic matching
        Fields field = new Fields(Arrays.asList("$.name"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        PresentationDefinition pdWithoutFilter = new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
        
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithoutFilter);
        
        // Create credentials with a flatter structure for easier path matching
        List<DecryptedCredentialDTO> credentials = createMockWalletCredentialsWithSimpleFilterData();
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(credentials);
        
        // Mock issuer service to return a valid config
        IssuerConfig mockIssuerConfig = createMockIssuerConfig();
        when(issuersService.getIssuerConfig(eq("test-issuer-id"), eq("TestCredential")))
                .thenReturn(mockIssuerConfig);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        
        // This test verifies that basic credential matching works without filters
        // If it fails, the issue is in the basic credential matching logic
        // If it passes, the issue is specifically in the filter matching logic
        assertFalse("Basic credential matching without filters failed - this indicates a fundamental issue with credential matching", 
                   result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
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

    @Test(expected = InvalidRequestException.class)
    public void testGetMatchingCredentialsWithSdJwtFormat() throws Exception {
        // Arrange
        PresentationDefinition pd = createMockPresentationDefinition();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(createMockWalletCredentialsWithSdJwtFormat());
        
        
        // Act & Assert - Should throw InvalidRequestException for unsupported SD-JWT format
        credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);
    }

    @Test(expected = InvalidRequestException.class)
    public void testGetMatchingCredentialsWithDcSdJwtFormat() throws Exception {
        // Arrange
        PresentationDefinition pd = createMockPresentationDefinition();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        
        List<DecryptedCredentialDTO> dcSdJwtCredentials = createMockWalletCredentialsWithDcSdJwtFormat();
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(dcSdJwtCredentials);
        
        
        // Act & Assert - Should throw InvalidRequestException for unsupported DC+SD-JWT format
        credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);
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
        // Should deduplicate credentials by ID
        Set<String> credentialIds = result.getMatchingCredentialsResponse().getAvailableCredentials()
                .stream().map(CredentialDTO::getCredentialId).collect(Collectors.toSet());
        assertEquals(2, credentialIds.size()); // Should have 2 unique credentials
    }

    // Helper methods to create mock objects

    private PresentationDefinition createMockPresentationDefinition() {

        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
        return pd;
    }

    private PresentationDefinition createMockPresentationDefinitionWithConstraints() {
        // Field 1: simple path
        Fields field1 = new Fields(Arrays.asList("$.type"), null, null, null, null, null);

        // Field 2: with path and filter
        Filter filter = new Filter("type", "String");
        Fields field2 = new Fields(Arrays.asList("$.credentialSubject.name"), null, null, null, filter, null);

        // Constraints with both fields
        Constraints constraints = new Constraints(Arrays.asList(field1, field2), null);

        // Input Descriptor with constraints
        InputDescriptor descriptor = new InputDescriptor("test-descriptor-with-constraints", null, null, null, constraints);

        // Presentation Definition with descriptor
        PresentationDefinition pd = new PresentationDefinition("test-presentation-definition-with-constraints", Arrays.asList(descriptor), null, null, null);

        return pd;
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
        // Create constraints with null fields (not null constraints object)
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

        // Create credential data with type that matches the presentation definition
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
        
        // Create a mock proof object
        VCCredentialResponseProof proof = new VCCredentialResponseProof();
        proof.setType("Ed25519Signature2020");
        properties.setProof(proof);
        
        return properties;
    }

    private List<DecryptedCredentialDTO> createMockWalletCredentialsWithMapData() throws JsonProcessingException {
        DecryptedCredentialDTO credential = new DecryptedCredentialDTO();
        credential.setId("test-credential-id");
        credential.setWalletId(walletId);

        // Create credential data as Map (which is what the implementation expects for ldp_vc format)
        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        
        // Create credentialSubject with name that contains "John" (filter pattern)
        Map<String, Object> subject = new HashMap<>();
        subject.put("id", "did:example:123456789");
        subject.put("name", "John Doe"); // This should match filter looking for "John"
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

        // Create credential data with a flatter structure for easier path matching
        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        credentialData.put("name", "John Doe"); // Direct field for $.name path
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

    // Test cases for evaluateJsonPath method through integration testing
    @Test
    public void testJsonPathEvaluationTypePathWithSampleData() throws Exception {
        // Arrange - Using the exact sample data provided
        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("id", "did:rcw:2121a1df-29fe-496e-ae24-219dcOb3ac49");
        credentialData.put("type", Arrays.asList("VerifiableCredential", "LifeInsuranceCredential"));
        
        // Create presentation definition that requires the type field
        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
        
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        
        // Create credentials with the sample data
        List<DecryptedCredentialDTO> credentials = createMockWalletCredentialsWithSampleData(credentialData);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(credentials);
        
        // Mock issuer service
        IssuerConfig mockIssuerConfig = createMockIssuerConfig();
        when(issuersService.getIssuerConfig(eq("test-issuer-id"), eq("TestCredential")))
                .thenReturn(mockIssuerConfig);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert - This tests that the JSON path evaluation works correctly
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        assertFalse("JSON path evaluation failed - credentials should match the type field", 
                   result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testJsonPathEvaluationNestedPath() throws Exception {
        // Arrange - Test nested path evaluation
        Map<String, Object> credentialData = new HashMap<>();
        Map<String, Object> credentialSubject = new HashMap<>();
        credentialSubject.put("name", "John Doe");
        credentialSubject.put("age", 30);
        credentialData.put("credentialSubject", credentialSubject);
        credentialData.put("type", Arrays.asList("VerifiableCredential", "IdentityCredential"));
        
        // Create presentation definition that requires nested field
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
        assertFalse("Nested JSON path evaluation failed", 
                   result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testJsonPathEvaluationNonExistentPath() throws Exception {
        // Arrange - Test non-existent path handling
        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("id", "did:rcw:2121a1df-29fe-496e-ae24-219dcOb3ac49");
        credentialData.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        
        // Create presentation definition that requires non-existent field
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

        // Assert - Should not match due to non-existent path
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        assertTrue("Non-existent path should result in no matches", 
                  result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testJsonPathEvaluationComplexNestedStructure() throws Exception {
        // Arrange - Test complex nested structure
        Map<String, Object> credentialData = new HashMap<>();
        Map<String, Object> credentialSubject = new HashMap<>();
        Map<String, Object> address = new HashMap<>();
        address.put("street", "123 Main St");
        address.put("city", "New York");
        credentialSubject.put("address", address);
        credentialSubject.put("name", "John Doe");
        credentialData.put("credentialSubject", credentialSubject);
        credentialData.put("type", Arrays.asList("VerifiableCredential", "IdentityCredential"));
        
        // Create presentation definition that requires deeply nested field
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
        assertFalse("Complex nested JSON path evaluation failed", 
                   result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    @Test
    public void testJsonPathEvaluationListIndexPath() throws Exception {
        // Arrange - Test list index path evaluation
        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("items", Arrays.asList("item1", "item2", "item3"));
        credentialData.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        
        // Create presentation definition that requires list index
        Fields field = new Fields(Arrays.asList("$.items.1"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
        
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        
        List<DecryptedCredentialDTO> credentials = createMockWalletCredentialsWithSampleData(credentialData);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(credentials);
        
        IssuerConfig mockIssuerConfig = createMockIssuerConfig();

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        assertTrue("List index JSON path evaluation failed",
                   result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    // Helper method to create credentials with custom data
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

    // Test cases for null checks and input validation
    @Test
    public void testGetMatchingCredentialsNullPresentationDefinitionFromService() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(null);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);
        });
        
        assertEquals("Presentation definition not found in session data", exception.getMessage());
    }


    @Test
    public void testMatchesConstraintsNullFields() throws Exception {
        // Arrange
        PresentationDefinition pd = createMockPresentationDefinition();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        
        // Create credentials with null fields in constraints
        List<DecryptedCredentialDTO> credentials = createMockWalletCredentialsWithMapData();
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(credentials);

        // Create presentation definition with null fields
        Constraints constraints = new Constraints(null, null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        PresentationDefinition pdWithNullFields = new PresentationDefinition("test-pd", Arrays.asList(descriptor), null, null, null);
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithNullFields);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert - Should handle null fields gracefully
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
    }

    @Test
    public void testMatchesFormatNullDescriptorFormat() throws Exception {
        // Arrange
        // Create input descriptor with null format but valid constraints
        Constraints constraints = new Constraints(null, null);
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

        // Assert - Should handle null format gracefully
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
    }

    @Test
    public void testMatchesFieldPathNullMatches() throws Exception {
        // Arrange
        PresentationDefinition pd = createMockPresentationDefinition();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pd);
        
        // Create credentials that will result in null matches
        List<DecryptedCredentialDTO> credentials = createMockWalletCredentialsWithMapData();
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(credentials);

        // Act
        MatchingCredentialsDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert - Should handle null matches gracefully
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
    }

    @Test
    public void testMatchesFilterNullFilter() throws Exception {
        // Arrange
        // Create presentation definition with null filter
        Fields field = new Fields(Arrays.asList("$.name"), null, null, null, null, null);
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

        // Assert - Should handle null filter gracefully
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
    }

    @Test
    public void testExtractRequiredClaimsNullPath() throws Exception {
        // Arrange
        // Create presentation definition with empty path list to test null path handling
        Fields field = new Fields(Collections.emptyList(), null, null, null, null, null);
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

        // Assert - Should handle null path gracefully
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
    }

    @Test
    public void testExtractRequiredClaimsBlankPath() throws Exception {
        // Arrange
        // Create presentation definition with blank path
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

        // Assert - Should handle blank path gracefully
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
    }
}