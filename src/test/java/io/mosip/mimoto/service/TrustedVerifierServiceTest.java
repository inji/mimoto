package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.TrustedVerifierRequest;
import io.mosip.mimoto.dto.TrustedVerifierResponseDTO;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.model.TrustedVerifier;
import io.mosip.mimoto.repository.VerifierRepository;
import io.mosip.mimoto.service.impl.TrustedVerifierServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static io.mosip.mimoto.exception.ErrorConstants.DUPLICATE_VERIFIER;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class TrustedVerifierServiceTest {

    @Mock
    private VerifierRepository verifierRepository;

    @InjectMocks
    private TrustedVerifierServiceImpl trustedVerifierService;

    private TrustedVerifierRequest request;
    private String walletId;

    @BeforeEach
    void setUp() {
        walletId = "test-wallet-id";
        request = new TrustedVerifierRequest();
        request.setVerifierId("test-verifier-id");
    }

    @Test
    void testAddTrustedVerifierSuccess() {
        // Given
        when(verifierRepository.existsByWalletIdAndVerifierId(walletId, request.getVerifierId()))
                .thenReturn(false);

        TrustedVerifier savedVerifier = TrustedVerifier.builder()
                .id("generated-uuid")
                .walletId(walletId)
                .verifierId(request.getVerifierId())
                .build();

        when(verifierRepository.save(any(TrustedVerifier.class))).thenReturn(savedVerifier);

        // When
        TrustedVerifierResponseDTO response = trustedVerifierService.addTrustedVerifier(walletId, request);

        // Then
        assertNotNull(response);
        assertEquals("generated-uuid", response.getId());

        verify(verifierRepository).existsByWalletIdAndVerifierId(walletId, request.getVerifierId());
        verify(verifierRepository).save(any(TrustedVerifier.class));
    }

    @Test
    void testAddTrustedVerifierDuplicateThrowsException() {
        // Given
        when(verifierRepository.existsByWalletIdAndVerifierId(walletId, request.getVerifierId()))
                .thenReturn(true);

        // When & Then
        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> trustedVerifierService.addTrustedVerifier(walletId, request));

        assertEquals(DUPLICATE_VERIFIER.getErrorCode(), exception.getErrorCode());
        assertEquals(DUPLICATE_VERIFIER.getErrorMessage(), exception.getErrorText());

        verify(verifierRepository).existsByWalletIdAndVerifierId(walletId, request.getVerifierId());
        verifyNoMoreInteractions(verifierRepository);
    }

    @Test
    void testAddTrustedVerifierWithNullWalletId() {
        // Given
        String nullWalletId = null;

        when(verifierRepository.existsByWalletIdAndVerifierId(nullWalletId, request.getVerifierId()))
                .thenReturn(false);

        TrustedVerifier savedVerifier = TrustedVerifier.builder()
                .id("generated-uuid")
                .walletId(nullWalletId)
                .verifierId(request.getVerifierId())
                .build();

        when(verifierRepository.save(any(TrustedVerifier.class))).thenReturn(savedVerifier);

        // When
        TrustedVerifierResponseDTO response = trustedVerifierService.addTrustedVerifier(nullWalletId, request);

        // Then
        assertNotNull(response);
        assertEquals("generated-uuid", response.getId());

        verify(verifierRepository).existsByWalletIdAndVerifierId(nullWalletId, request.getVerifierId());
        verify(verifierRepository).save(any(TrustedVerifier.class));
    }

    @Test
    void testAddTrustedVerifierWithNullRequest() {
        // Given
        TrustedVerifierRequest nullRequest = null;

        // When & Then
        assertThrows(NullPointerException.class,
                () -> trustedVerifierService.addTrustedVerifier(walletId, nullRequest));

        verifyNoInteractions(verifierRepository);
    }

    @Test
    void testAddTrustedVerifierWithNullVerifierId() {
        // Given
        request.setVerifierId(null);

        when(verifierRepository.existsByWalletIdAndVerifierId(walletId, null))
                .thenReturn(false);

        TrustedVerifier savedVerifier = TrustedVerifier.builder()
                .id("generated-uuid")
                .walletId(walletId)
                .verifierId(null)
                .build();

        when(verifierRepository.save(any(TrustedVerifier.class))).thenReturn(savedVerifier);

        // When
        TrustedVerifierResponseDTO response = trustedVerifierService.addTrustedVerifier(walletId, request);

        // Then
        assertNotNull(response);
        assertEquals("generated-uuid", response.getId());

        verify(verifierRepository).existsByWalletIdAndVerifierId(walletId, null);
        verify(verifierRepository).save(any(TrustedVerifier.class));
    }

    @Test
    void testAddTrustedVerifierRepositorySaveReturnsNull() {
        // Given
        when(verifierRepository.existsByWalletIdAndVerifierId(walletId, request.getVerifierId()))
                .thenReturn(false);

        when(verifierRepository.save(any(TrustedVerifier.class))).thenReturn(null);

        // When & Then
        assertThrows(NullPointerException.class,
                () -> trustedVerifierService.addTrustedVerifier(walletId, request));

        verify(verifierRepository).existsByWalletIdAndVerifierId(walletId, request.getVerifierId());
        verify(verifierRepository).save(any(TrustedVerifier.class));
    }

    @Test
    void testAddTrustedVerifierWithEmptyStrings() {
        // Given
        String emptyWalletId = "";
        request.setVerifierId("");

        when(verifierRepository.existsByWalletIdAndVerifierId(emptyWalletId, ""))
                .thenReturn(false);

        TrustedVerifier savedVerifier = TrustedVerifier.builder()
                .id("generated-uuid")
                .walletId(emptyWalletId)
                .verifierId("")
                .build();

        when(verifierRepository.save(any(TrustedVerifier.class))).thenReturn(savedVerifier);

        // When
        TrustedVerifierResponseDTO response = trustedVerifierService.addTrustedVerifier(emptyWalletId, request);

        // Then
        assertNotNull(response);
        assertEquals("generated-uuid", response.getId());

        verify(verifierRepository).existsByWalletIdAndVerifierId(emptyWalletId, "");
        verify(verifierRepository).save(any(TrustedVerifier.class));
    }

    @Test
    void testAddTrustedVerifierRepositoryThrowsException() {
        // Given
        when(verifierRepository.existsByWalletIdAndVerifierId(walletId, request.getVerifierId()))
                .thenReturn(false);

        when(verifierRepository.save(any(TrustedVerifier.class)))
                .thenThrow(new RuntimeException("Database error"));

        // When & Then
        assertThrows(RuntimeException.class,
                () -> trustedVerifierService.addTrustedVerifier(walletId, request));

        verify(verifierRepository).existsByWalletIdAndVerifierId(walletId, request.getVerifierId());
        verify(verifierRepository).save(any(TrustedVerifier.class));
    }
}