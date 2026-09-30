package io.mosip.mimoto.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.TrustedVerifierRequest;
import io.mosip.mimoto.dto.TrustedVerifierResponseDTO;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.service.TrustedVerifierService;
import io.mosip.mimoto.util.GlobalExceptionHandler;
import io.mosip.mimoto.util.WalletUtil;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static io.mosip.mimoto.exception.ErrorConstants.DUPLICATE_VERIFIER;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class WalletTrustedVerifiersControllerTest {

    @Mock
    private TrustedVerifierService trustedVerifierService;

    @InjectMocks
    private WalletTrustedVerifiersController controller;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;
    private MockHttpSession session;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setMessageConverters(new MappingJackson2HttpMessageConverter())
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
        objectMapper = new ObjectMapper();
        session = new MockHttpSession();
    }

    @Test
    void testAddTrustedVerifierSuccess() throws Exception {
        // Given
        String walletId = "test-wallet-id";
        TrustedVerifierRequest request = new TrustedVerifierRequest();
        request.setVerifierId("test-verifier-id");

        TrustedVerifierResponseDTO response = new TrustedVerifierResponseDTO();
        response.setId("generated-id");

        try (MockedStatic<WalletUtil> walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(any(HttpSession.class), eq(walletId)))
                    .thenAnswer(invocation -> null);

            when(trustedVerifierService.addTrustedVerifier(walletId, request)).thenReturn(response);

            // When & Then
            mockMvc.perform(post("/wallets/{walletId}/trusted-verifiers", walletId)
                            .session(session)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.id").value("generated-id"));

            verify(trustedVerifierService).addTrustedVerifier(walletId, request);
        }
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void testAddTrustedVerifierInvalidVerifierId(String verifierId) throws Exception {
        String walletId = "test-wallet-id";
        TrustedVerifierRequest request = new TrustedVerifierRequest();
        request.setVerifierId(verifierId);

        try (MockedStatic<WalletUtil> walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(any(HttpSession.class), eq(walletId)))
                    .thenAnswer(invocation -> null);

            mockMvc.perform(post("/wallets/{walletId}/trusted-verifiers", walletId)
                            .session(session)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorCode").value("invalid_request"));

            verifyNoInteractions(trustedVerifierService);
        }
    }

    @Test
    void testAddTrustedVerifierDuplicateVerifier() throws Exception {
        // Given
        String walletId = "test-wallet-id";
        TrustedVerifierRequest request = new TrustedVerifierRequest();
        request.setVerifierId("existing-verifier-id");

        try (MockedStatic<WalletUtil> walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(any(HttpSession.class), eq(walletId)))
                    .thenAnswer(invocation -> null);

            when(trustedVerifierService.addTrustedVerifier(walletId, request))
                    .thenThrow(new InvalidRequestException(DUPLICATE_VERIFIER.getErrorCode(), DUPLICATE_VERIFIER.getErrorMessage()));

            // When & Then
            mockMvc.perform(post("/wallets/{walletId}/trusted-verifiers", walletId)
                            .session(session)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorCode").exists());

            verify(trustedVerifierService).addTrustedVerifier(walletId, request);
        }
    }


    @Test
    void testAddTrustedVerifierWalletValidationFailure() throws Exception {
        // Given
        String walletId = "invalid-wallet-id";
        TrustedVerifierRequest request = new TrustedVerifierRequest();
        request.setVerifierId("test-verifier-id");

        try (MockedStatic<WalletUtil> walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(any(HttpSession.class), eq(walletId)))
                    .thenThrow(new RuntimeException("Invalid wallet ID"));

            // When & Then
            mockMvc.perform(post("/wallets/{walletId}/trusted-verifiers", walletId)
                            .session(session)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isInternalServerError())
                    .andExpect(jsonPath("$.errorCode").exists());

            verifyNoInteractions(trustedVerifierService);
        }
    }

    @Test
    void testAddTrustedVerifierServiceException() throws Exception {
        // Given
        String walletId = "test-wallet-id";
        TrustedVerifierRequest request = new TrustedVerifierRequest();
        request.setVerifierId("test-verifier-id");

        try (MockedStatic<WalletUtil> walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(any(HttpSession.class), eq(walletId)))
                    .thenAnswer(invocation -> null);

            when(trustedVerifierService.addTrustedVerifier(walletId, request))
                    .thenThrow(new RuntimeException("Database connection failed"));

            // When & Then
            mockMvc.perform(post("/wallets/{walletId}/trusted-verifiers", walletId)
                            .session(session)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isInternalServerError())
                    .andExpect(jsonPath("$.errorCode").exists());

            verify(trustedVerifierService).addTrustedVerifier(walletId, request);
        }
    }

    @Test
    void testAddTrustedVerifierServiceDataAccessException() throws Exception {
        String walletId = "test-wallet-id";
        TrustedVerifierRequest request = new TrustedVerifierRequest();
        request.setVerifierId("test-verifier-id");

        try (MockedStatic<WalletUtil> walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(any(HttpSession.class), eq(walletId)))
                    .thenAnswer(invocation -> null);

            when(trustedVerifierService.addTrustedVerifier(walletId, request))
                    .thenThrow(new DataAccessResourceFailureException("DB down"));

            mockMvc.perform(post("/wallets/{walletId}/trusted-verifiers", walletId)
                            .session(session)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isInternalServerError())
                    .andExpect(jsonPath("$.errorCode").exists());

            verify(trustedVerifierService).addTrustedVerifier(walletId, request);
        }
    }

}