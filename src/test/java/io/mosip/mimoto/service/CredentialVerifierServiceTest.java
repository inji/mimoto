package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.CredentialVerificationResult;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponseProof;
import io.mosip.mimoto.exception.CredentialStatusException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.model.CredentialStatusCheck;
import io.mosip.mimoto.service.impl.CredentialVerifierServiceImpl;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.CredentialStatusResult;
import io.mosip.vercred.vcverifier.data.CredentialVerificationSummary;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode;
import io.mosip.vercred.vcverifier.exception.StatusCheckException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

@RunWith(MockitoJUnitRunner.class)
public class CredentialVerifierServiceTest {

    private static final List<String> DEFAULT_STATUS_PURPOSES = List.of("revocation", "suspension");

    private CredentialVerifierServiceImpl credentialVerifier;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private CredentialsVerifier credentialsVerifier;

    @Mock
    private VerificationResult verificationResult;

    private VCCredentialResponse vcCredentialResponse;

    private final String credentialJson = "{\"credential\":\"test\"}";

    @Before
    public void setUp() throws Exception {
        credentialVerifier = new CredentialVerifierServiceImpl(objectMapper, credentialsVerifier, DEFAULT_STATUS_PURPOSES);
        VCCredentialProperties credentialProperties = VCCredentialProperties.builder()
                .type(Arrays.asList("VerifiableCredential", "test"))
                .credentialSubject(Map.of("name", "John Doe"))
                .proof(new VCCredentialResponseProof())
                .build();

        vcCredentialResponse = VCCredentialResponse.builder()
                .format(CredentialFormat.LDP_VC.getValue())
                .credential(credentialProperties)
                .build();

        lenient().when(objectMapper.writeValueAsString(any())).thenReturn(credentialJson);
    }

    @Test
    public void testVerifySuccess() throws Exception {
        // Arrange
        when(verificationResult.getVerificationStatus()).thenReturn(true);
        when(credentialsVerifier.verifyAndGetCredentialStatus(eq(credentialJson), eq(CredentialFormat.LDP_VC), eq(DEFAULT_STATUS_PURPOSES)))
                .thenReturn(new CredentialVerificationSummary(verificationResult, Map.of()));

        CredentialVerificationResult result = credentialVerifier.verify(vcCredentialResponse);

        assertNotNull(result);
        verify(credentialsVerifier).verifyAndGetCredentialStatus(credentialJson, CredentialFormat.LDP_VC, DEFAULT_STATUS_PURPOSES);
        verify(credentialsVerifier, never()).verify(anyString(), any());
        verify(credentialsVerifier, never()).getCredentialStatus(anyString(), any(), anyList());
    }

    @Test(expected = VCVerificationException.class)
    public void testVerifyFailureThrowsException() throws Exception {
        // Arrange
        when(verificationResult.getVerificationStatus()).thenReturn(false);
        when(verificationResult.getVerificationErrorCode()).thenReturn("ERR_CODE");
        when(verificationResult.getVerificationMessage()).thenReturn("Verification failed");
        when(credentialsVerifier.verifyAndGetCredentialStatus(eq(credentialJson), eq(CredentialFormat.LDP_VC), eq(DEFAULT_STATUS_PURPOSES)))
                .thenReturn(new CredentialVerificationSummary(verificationResult, Map.of()));

        // Act
        credentialVerifier.verify(vcCredentialResponse);
    }

    @Test(expected = JsonProcessingException.class)
    public void testVerifyJsonProcessingException() throws Exception {
        // Arrange
        when(objectMapper.writeValueAsString(any())).thenThrow(JsonProcessingException.class);

        // Act
        credentialVerifier.verify(vcCredentialResponse);
    }

    @Test
    public void should_returnStatusPurposes_when_ldpVcVerificationSucceeds() throws Exception {
        when(verificationResult.getVerificationStatus()).thenReturn(true);
        when(credentialsVerifier.verifyAndGetCredentialStatus(eq(credentialJson), eq(CredentialFormat.LDP_VC), eq(DEFAULT_STATUS_PURPOSES)))
                .thenReturn(new CredentialVerificationSummary(verificationResult,
                        Map.of("revocation", new CredentialStatusResult(true, null),
                                "suspension", new CredentialStatusResult(true, null))));

        CredentialVerificationResult verification = credentialVerifier.verify(vcCredentialResponse);

        assertEquals(2, verification.getStatusChecks().size());
        assertTrue(verification.getStatusChecks().stream().allMatch(CredentialStatusCheck::isValid));
        verify(credentialsVerifier, never()).verify(anyString(), any());
        verify(credentialsVerifier, never()).getCredentialStatus(anyString(), any(), anyList());
    }

    @Test
    public void should_returnEmptyStatusChecks_when_mdocHasNoStatusReference() throws Exception {
        mockMdocStatus(Map.of());

        assertTrue(credentialVerifier.verify(mdocResponse()).getStatusChecks().isEmpty());
    }

    @Test
    public void should_storeRevocationOnly_when_mdocBits1IsValid() throws Exception {
        mockMdocStatus(Map.of("revocation", new CredentialStatusResult(true, null)));

        CredentialVerificationResult verification = credentialVerifier.verify(mdocResponse());

        assertEquals(1, verification.getStatusChecks().size());
        assertEquals("revocation", verification.getStatusChecks().get(0).getPurpose());
        assertTrue(verification.getStatusChecks().get(0).isValid());
    }

    @Test
    public void should_storeBothPurposes_when_mdocBits2IsValid() throws Exception {
        mockMdocStatus(Map.of(
                "revocation", new CredentialStatusResult(true, null),
                "suspension", new CredentialStatusResult(true, null)));

        CredentialVerificationResult verification = credentialVerifier.verify(mdocResponse());

        assertEquals(2, verification.getStatusChecks().size());
        assertTrue(verification.getStatusChecks().stream().allMatch(CredentialStatusCheck::isValid));
    }

    @Test
    public void should_returnInvalidRevocation_when_mdocIsRevoked() throws Exception {
        mockMdocStatus(Map.of("revocation", new CredentialStatusResult(false, null)));

        CredentialVerificationResult verification = credentialVerifier.verify(mdocResponse());

        assertEquals(1, verification.getStatusChecks().size());
        assertEquals("revocation", verification.getStatusChecks().get(0).getPurpose());
        assertFalse(verification.getStatusChecks().get(0).isValid());
    }

    @Test
    public void should_returnInvalidSuspension_when_mdocIsSuspended() throws Exception {
        mockMdocStatus(Map.of("suspension", new CredentialStatusResult(false, null)));

        CredentialVerificationResult verification = credentialVerifier.verify(mdocResponse());

        assertEquals(1, verification.getStatusChecks().size());
        assertEquals("suspension", verification.getStatusChecks().get(0).getPurpose());
        assertFalse(verification.getStatusChecks().get(0).isValid());
    }

    @Test
    public void should_throwUnavailable_when_statusListCheckFails() throws Exception {
        StatusCheckException error = new StatusCheckException("fetch failed", StatusCheckErrorCode.STATUS_RETRIEVAL_ERROR);
        mockMdocStatus(Map.of(
                "revocation", new CredentialStatusResult(false, error),
                "suspension", new CredentialStatusResult(false, error)));

        CredentialStatusException exception = assertThrows(CredentialStatusException.class,
                () -> credentialVerifier.verify(mdocResponse()));
        assertEquals(ErrorConstants.CREDENTIAL_STATUS_UNAVAILABLE.getErrorCode(), exception.getErrorCode());
        assertFalse(exception.isExpired());
    }

    @Test
    public void should_preserveExpired_when_statusListCheckFailsAndVcIsExpired() throws Exception {
        StatusCheckException error = new StatusCheckException("fetch failed", StatusCheckErrorCode.STATUS_RETRIEVAL_ERROR);
        when(verificationResult.getVerificationStatus()).thenReturn(true);
        when(verificationResult.getVerificationErrorCode()).thenReturn("ERR_VC_EXPIRED");
        when(credentialsVerifier.verifyAndGetCredentialStatus(eq(MDOC), eq(CredentialFormat.MSO_MDOC), eq(DEFAULT_STATUS_PURPOSES)))
                .thenReturn(new CredentialVerificationSummary(verificationResult,
                        Map.of("revocation", new CredentialStatusResult(false, error))));

        CredentialStatusException exception = assertThrows(CredentialStatusException.class,
                () -> credentialVerifier.verify(mdocResponse()));
        assertEquals(ErrorConstants.CREDENTIAL_STATUS_UNAVAILABLE.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.isExpired());
    }

    @Test
    public void should_setExpiredTrue_when_cryptoPassesAndVcIsExpired() throws Exception {
        when(verificationResult.getVerificationStatus()).thenReturn(true);
        when(verificationResult.getVerificationErrorCode()).thenReturn("ERR_VC_EXPIRED");
        when(credentialsVerifier.verifyAndGetCredentialStatus(eq(MDOC), eq(CredentialFormat.MSO_MDOC), eq(DEFAULT_STATUS_PURPOSES)))
                .thenReturn(new CredentialVerificationSummary(verificationResult,
                        Map.of("revocation", new CredentialStatusResult(true, null))));

        CredentialVerificationResult verification = credentialVerifier.verify(mdocResponse());

        assertTrue(verification.isExpired());
        assertEquals(1, verification.getStatusChecks().size());
        assertTrue(verification.getStatusChecks().get(0).isValid());
    }

    @Test
    public void should_throwVcVerificationException_when_cryptoFailsForExpiredMdoc() throws Exception {
        when(verificationResult.getVerificationStatus()).thenReturn(false);
        when(verificationResult.getVerificationErrorCode()).thenReturn("ERR_VC_EXPIRED");
        when(verificationResult.getVerificationMessage()).thenReturn("Credential has expired");
        when(credentialsVerifier.verifyAndGetCredentialStatus(eq(MDOC), eq(CredentialFormat.MSO_MDOC), eq(DEFAULT_STATUS_PURPOSES)))
                .thenReturn(new CredentialVerificationSummary(verificationResult, Map.of()));

        VCVerificationException walletException = assertThrows(VCVerificationException.class,
                () -> credentialVerifier.verify(mdocResponse()));
        assertEquals("err_vc_expired", walletException.getErrorCode());
    }

    @Test
    public void should_throwVcVerificationException_when_mdocSignatureFails() throws Exception {
        when(verificationResult.getVerificationStatus()).thenReturn(false);
        when(verificationResult.getVerificationErrorCode()).thenReturn("ERR_SIGNATURE_VERIFICATION_FAILED");
        when(verificationResult.getVerificationMessage()).thenReturn("Verification failed");
        when(credentialsVerifier.verifyAndGetCredentialStatus(eq(MDOC), eq(CredentialFormat.MSO_MDOC), eq(DEFAULT_STATUS_PURPOSES)))
                .thenReturn(new CredentialVerificationSummary(verificationResult, Map.of()));

        VCVerificationException exception = assertThrows(VCVerificationException.class,
                () -> credentialVerifier.verify(mdocResponse()));
        assertFalse(exception instanceof CredentialStatusException);
        verify(credentialsVerifier, never()).verify(anyString(), any());
        verify(credentialsVerifier, never()).getCredentialStatus(anyString(), any(), anyList());
    }

    private static final String MDOC = "o2d2ZXJzaW9uYzEuMA";

    private VCCredentialResponse mdocResponse() {
        return VCCredentialResponse.builder()
                .format(CredentialFormat.MSO_MDOC.getValue())
                .credential(MDOC)
                .build();
    }

    private void mockMdocStatus(Map<String, CredentialStatusResult> statuses) {
        when(verificationResult.getVerificationStatus()).thenReturn(true);
        when(credentialsVerifier.verifyAndGetCredentialStatus(eq(MDOC), eq(CredentialFormat.MSO_MDOC), eq(DEFAULT_STATUS_PURPOSES)))
                .thenReturn(new CredentialVerificationSummary(verificationResult, statuses));
    }

    @Test(expected = NullPointerException.class)
    public void testVerifyWithNullCredential() throws Exception {
        // Arrange
        VCCredentialResponse nullCredentialResponse = VCCredentialResponse.builder()
                .format(CredentialFormat.LDP_VC.getValue())
                .credential(null)
                .build();

        // Act
        credentialVerifier.verify(nullCredentialResponse);
    }
}
