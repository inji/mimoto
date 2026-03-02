package io.mosip.mimoto.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.UnauthorizedAccessException;
import io.mosip.mimoto.exception.WalletLockedException;
import io.mosip.mimoto.model.WalletLockStatus;
import io.mosip.mimoto.service.WalletService;
import io.mosip.mimoto.util.GlobalExceptionHandler;
import io.mosip.mimoto.util.WalletValidator;
import jakarta.servlet.http.HttpSession;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.List;

import static io.mosip.mimoto.util.TestUtilities.createRequestBody;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {WalletsController.class, GlobalExceptionHandler.class})
@AutoConfigureMockMvc
@EnableWebMvc
@EnableWebSecurity
public class WalletsControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private WalletService walletService;

    @MockBean
    private WalletValidator walletValidator;

    CreateWalletRequestDto createWalletRequestDto;

    MockHttpSession mockSession;

    String userId, walletName, walletPin, confirmWalletPin, walletId;

    @Before
    public void setUp() {
        walletName = "My Wallet";
        walletPin = "1234";
        confirmWalletPin = "1234";
        walletId = "walletId123";
        createWalletRequestDto = new CreateWalletRequestDto();
        createWalletRequestDto.setWalletName(walletName);
        createWalletRequestDto.setWalletPin(walletPin);
        createWalletRequestDto.setConfirmWalletPin(confirmWalletPin);
        mockSession = new MockHttpSession();
        mockSession.setAttribute("clientRegistrationId", "google");
        mockSession.setAttribute(SessionKeys.USER_ID, "user123");
        userId = (String) mockSession.getAttribute(SessionKeys.USER_ID);
    }

    // Test for creating a wallet

    @Test
    public void shouldReturnWalletIdForSuccessfulWalletCreation() throws Exception {
        when(walletService.createWallet(userId, walletName, walletPin, confirmWalletPin)).thenReturn(
                WalletResponseDto.builder().walletId(walletId).walletName(walletName).build());

        mockMvc.perform(post("/wallets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(createWalletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"walletId\": \"walletId123\",\"walletName\": \"My Wallet\"}", true));
    }

    @Test
    public void shouldThrowExceptionIfAnyErrorOccurredWhenCreatingWallet() throws Exception {
        when(walletService.createWallet(userId, walletName, walletPin, confirmWalletPin))
                .thenThrow(new RuntimeException("Exception occurred when creating Wallet for given userId"));

        mockMvc.perform(post("/wallets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(createWalletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("internal_server_error"))
                .andExpect(jsonPath("$.errorMessage").value("We are unable to process request now"));
    }

    @Test
    public void shouldThrowExceptionIfReceivedPINAndConfirmPINDoNotMatch() throws Exception {
        createWalletRequestDto.setConfirmWalletPin("2345");
        when(walletService.createWallet(userId, walletName, walletPin, "2345"))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Entered PIN and Confirm PIN do not match"));

        mockMvc.perform(post("/wallets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(createWalletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Entered PIN and Confirm PIN do not match"));
    }

    @Test
    public void shouldReturnUnauthorizedWhenUserIdIsMissingForCreateWallet() throws Exception {
        mockSession.clearAttributes();
        MockHttpSession sessionWithoutUserId = mockSession;
        doThrow(new UnauthorizedAccessException(ErrorConstants.UNAUTHORIZED_ACCESS.getErrorCode(), "User ID not found in session")).when(walletService).createWallet(null, walletName, walletPin, confirmWalletPin);

        mockMvc.perform(post("/wallets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(createWalletRequestDto))
                        .session(sessionWithoutUserId)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("unauthorized"))
                .andExpect(jsonPath("$.errorMessage").value("User ID not found in session"));
    }

    // Test for fetching wallets

    @Test
    public void shouldReturnListOfWalletIDsForValidUserId() throws Exception {
        List<WalletDetailsResponseDto> wallets = List.of(new WalletDetailsResponseDto("walletId1", "Wallet1", null),
                new WalletDetailsResponseDto("walletId2", "Wallet2", WalletLockStatus.TEMPORARILY_LOCKED));
        when(walletService.getWallets(userId)).thenReturn(wallets);

        mockMvc.perform(get("/wallets")
                        .accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("[{\"walletId\":\"walletId1\",\"walletName\":\"Wallet1\",\"walletStatus\":null},{\"walletId\":\"walletId2\",\"walletName\":\"Wallet2\",\"walletStatus\":\"temporarily_locked\"}]"));
    }

    @Test
    public void shouldThrowExceptionIfAnyErrorOccurredWhileFetchingWalletsForGivenUserId() throws Exception {
        when(walletService.getWallets(userId)).thenThrow(new RuntimeException("Exception occurred when fetching the wallets for given userId"));

        mockMvc.perform(get("/wallets")
                        .session(mockSession)
                        .accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("internal_server_error"))
                .andExpect(jsonPath("$.errorMessage").value("We are unable to process request now"));
    }

    // Test for deleting a wallet

    @Test
    public void shouldDeleteWalletSuccessfully() throws Exception {
        mockMvc.perform(delete(String.format("/wallets/%s", walletId))
                        .accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk());
    }

    @Test
    public void shouldClearSessionAttributesWhenDeletingCurrentWallet() throws Exception {
        mockSession.setAttribute(SessionKeys.WALLET_ID, walletId);
        mockSession.setAttribute(SessionKeys.WALLET_KEY, "walletKey123");

        mockMvc.perform(delete(String.format("/wallets/%s", walletId))
                        .accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk());

        // Session attributes should be cleared
        assertEquals(null, mockSession.getAttribute(SessionKeys.WALLET_ID));
        assertEquals(null, mockSession.getAttribute(SessionKeys.WALLET_KEY));
    }

    @Test
    public void shouldReturnUnauthorizedWhenUserIdIsMissingForDeleteWallet() throws Exception {
        mockSession.clearAttributes();
        MockHttpSession sessionWithoutUserId = mockSession;
        doThrow(new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "User ID cannot be null or empty")).when(walletService).deleteWallet(null, walletId);

        mockMvc.perform(delete(String.format("/wallets/%s", walletId))
                        .accept(MediaType.APPLICATION_JSON)
                        .session(sessionWithoutUserId)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("User ID cannot be null or empty"));
    }

    @Test
    public void shouldReturnBadRequestWhenInvalidRequestExceptionIsThrownByService() throws Exception {
        doThrow(new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Wallet not found")).when(walletService).deleteWallet(userId, walletId);

        mockMvc.perform(delete("/wallets/" + walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet not found"));
    }

    // Unlock wallet tests

    @Test
    public void shouldUnlockWalletSuccessfully() throws Exception {
        String decryptedWalletKey = "decryptedKey";
        UnlockWalletRequestDto unlockRequest = new UnlockWalletRequestDto();
        unlockRequest.setWalletPin(walletPin);

        when(walletService.unlockWallet(walletId, walletPin, userId)).thenReturn(new WalletResponseDto(walletId, walletName, decryptedWalletKey));

        MvcResult result = mockMvc.perform(post("/wallets/{walletId}/unlock", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(unlockRequest))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.walletId").value(walletId))
                .andReturn();

        HttpSession httpSession = result.getRequest().getSession();
        assertEquals(httpSession.getAttribute(SessionKeys.WALLET_ID), walletId);
        assertEquals(httpSession.getAttribute(SessionKeys.WALLET_KEY), decryptedWalletKey);
    }

    @Test
    public void shouldThrowExceptionWhenUserIdIsMissingForUnlockWallet() throws Exception {
        UnlockWalletRequestDto unlockRequest = new UnlockWalletRequestDto();
        unlockRequest.setWalletPin(walletPin);
        when(walletService.unlockWallet(walletId, walletPin, null))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "User ID cannot be null or empty"));
        mockSession.clearAttributes();
        MockHttpSession sessionWithoutUserId = mockSession;
        sessionWithoutUserId.setAttribute("clientRegistrationId", "google");

        mockMvc.perform(post("/wallets/{walletId}/unlock", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(unlockRequest))
                        .session(sessionWithoutUserId)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("User ID cannot be null or empty"));
    }

    @Test
    public void shouldThrowExceptionWhenWalletNotFoundForUnlock() throws Exception {
        String nonExistentWalletId = "nonExistentWalletId";
        UnlockWalletRequestDto unlockRequest = new UnlockWalletRequestDto();
        unlockRequest.setWalletPin(walletPin);

        when(walletService.unlockWallet(nonExistentWalletId, walletPin, userId))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Wallet not found"));

        mockMvc.perform(post("/wallets/{walletId}/unlock", nonExistentWalletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(unlockRequest))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet not found"));
    }

    @Test
    public void shouldThrowExceptionWhenInvalidPinProvidedForUnlock() throws Exception {
        String invalidPin = "invalidPin";
        UnlockWalletRequestDto unlockRequest = new UnlockWalletRequestDto();
        unlockRequest.setWalletPin(invalidPin);

        when(walletService.unlockWallet(walletId, invalidPin, userId))
                .thenThrow(new InvalidRequestException("invalid_pin", "Invalid PIN or wallet key provided"));

        mockMvc.perform(post("/wallets/{walletId}/unlock", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(unlockRequest))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_pin"))
                .andExpect(jsonPath("$.errorMessage").value("Invalid PIN or wallet key provided"));
    }

    @Test
    public void shouldThrowTemporarilyLockedExceptionWhenUnlockingWalletWhichIsAlreadyLockedTemporarily() throws Exception {
        UnlockWalletRequestDto unlockRequest = new UnlockWalletRequestDto();
        unlockRequest.setWalletPin(walletPin);

        String errorMessage = ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage() + " for 1 hour(s)";
        when(walletService.unlockWallet(walletId, walletPin, userId))
                .thenThrow(new WalletLockedException(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(), errorMessage));

        mockMvc.perform(post("/wallets/{walletId}/unlock", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(unlockRequest))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.errorCode").value(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode()))
                .andExpect(jsonPath("$.errorMessage").value(errorMessage));
    }

    @Test
    public void shouldThrowTemporarilyLockedExceptionWhenUnlockingWalletWithInvalidPinInLastAttemptBeforeTemporaryLock() throws Exception {
        UnlockWalletRequestDto unlockRequest = new UnlockWalletRequestDto();
        unlockRequest.setWalletPin("invalidPin");

        String errorMessage = ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage() + " for 1 hour(s)";
        when(walletService.unlockWallet(walletId, "invalidPin", userId))
                .thenThrow(new WalletLockedException(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(), errorMessage));

        mockMvc.perform(post("/wallets/{walletId}/unlock", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(unlockRequest))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.errorCode").value(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode()))
                .andExpect(jsonPath("$.errorMessage").value(errorMessage));
    }

    @Test
    public void shouldThrowPermanentlyLockedExceptionWhenUnlockingWalletWhichIsAlreadyLockedPermanently() throws Exception {
        UnlockWalletRequestDto unlockRequest = new UnlockWalletRequestDto();
        unlockRequest.setWalletPin(walletPin);

        String errorMessage = ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage();
        when(walletService.unlockWallet(walletId, walletPin, userId))
                .thenThrow(new WalletLockedException(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), errorMessage));

        mockMvc.perform(post("/wallets/{walletId}/unlock", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(unlockRequest))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.errorCode").value(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode()))
                .andExpect(jsonPath("$.errorMessage").value(errorMessage));
    }

    @Test
    public void shouldThrowExceptionWhenUnlockingWalletWithInvalidPinInLastSecondAttemptBeforePermanentLock() throws Exception {
        UnlockWalletRequestDto unlockRequest = new UnlockWalletRequestDto();
        unlockRequest.setWalletPin("invalidPin");

        String errorMessage = ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage();
        when(walletService.unlockWallet(walletId, "invalidPin", userId))
                .thenThrow(new InvalidRequestException(ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(), errorMessage));

        mockMvc.perform(post("/wallets/{walletId}/unlock", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(unlockRequest))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value(ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode()))
                .andExpect(jsonPath("$.errorMessage").value(errorMessage));
    }

    @Test
    public void shouldThrowPermanentlyLockedExceptionWhenUnlockingWalletWithInvalidPinInLastAttemptBeforePermanentLock() throws Exception {
        UnlockWalletRequestDto unlockRequest = new UnlockWalletRequestDto();
        unlockRequest.setWalletPin("invalidPin");

        String errorMessage = ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage();
        when(walletService.unlockWallet(walletId, "invalidPin", userId))
                .thenThrow(new WalletLockedException(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), errorMessage));

        mockMvc.perform(post("/wallets/{walletId}/unlock", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(unlockRequest))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.errorCode").value(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode()))
                .andExpect(jsonPath("$.errorMessage").value(errorMessage));
    }

    @Test
    public void shouldThrowExceptionForServerErrorDuringUnlock() throws Exception {
        UnlockWalletRequestDto unlockRequest = new UnlockWalletRequestDto();
        unlockRequest.setWalletPin(walletPin);

        when(walletService.unlockWallet(walletId, walletPin, userId))
                .thenThrow(new RuntimeException("Error decrypting wallet key"));

        mockMvc.perform(post("/wallets/{walletId}/unlock", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(unlockRequest))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("internal_server_error"))
                .andExpect(jsonPath("$.errorMessage").value("We are unable to process request now"));
    }

    @Test
    public void shouldThrowExceptionIfAnyErrorOccurredWhileFetchingWalletDataForGivenUserIdAndWalletId() throws Exception {
        when(walletService.unlockWallet(walletId, walletPin, userId)).thenThrow(new RuntimeException("Exception occurred when fetching the wallet data for given walletId and userId"));

        mockMvc.perform(post(String.format("/wallets/%s/unlock", walletId))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(createWalletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("internal_server_error"))
                .andExpect(jsonPath("$.errorMessage").value("We are unable to process request now"));
    }

    @Test
    public void shouldReturnWalletLockedErrorDetailsWhenWalletIDIsMissingInSession() throws Exception {
        mockSession.removeAttribute(SessionKeys.WALLET_ID);
        when(walletService.unlockWallet(walletId, walletPin, userId)).
                thenThrow(new InvalidRequestException("wallet_locked", "Wallet is locked"));

        mockMvc.perform(post(String.format("/wallets/%s/unlock", walletId))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(createWalletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("wallet_locked"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet is locked"));
    }

    @Test
    public void shouldReturnUnauthorizedWhenUserIdIsInvalidForCreateWallet() throws Exception {
        mockSession.setAttribute(SessionKeys.USER_ID, null);
        doThrow(new UnauthorizedAccessException(
                ErrorConstants.UNAUTHORIZED_ACCESS.getErrorCode(),
                "User ID not found in session"))
                .when(walletValidator).validateUserId(null);

        mockMvc.perform(post("/wallets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(createWalletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user("anonymous").roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("unauthorized"))
                .andExpect(jsonPath("$.errorMessage").value("User ID not found in session"));
    }

    @Test
    public void shouldCreateWalletWhenUserIdIsValidAndValidatorPasses() throws Exception {
        // validator is void -> use doNothing()
        org.mockito.Mockito.doNothing()
                .when(walletValidator)
                .validateUserId(userId);

        when(walletService.createWallet(userId, walletName, walletPin, confirmWalletPin))
                .thenReturn(new WalletResponseDto(walletId, walletName, null));

        mockMvc.perform(post("/wallets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(createWalletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.walletId").value(walletId))
                .andExpect(jsonPath("$.walletName").value(walletName));
    }
}