package io.mosip.mimoto.controller;

import com.jayway.jsonpath.JsonPath;
import io.mosip.mimoto.dto.VerifiableCredentialRequestDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.DPoPSessionService;
import io.mosip.mimoto.service.PkceSessionManager;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.GlobalExceptionHandler;
import jakarta.servlet.http.HttpSession;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.ByteArrayInputStream;
import java.util.Collections;
import java.util.List;

import static io.mosip.mimoto.exception.ErrorConstants.*;
import static io.mosip.mimoto.util.TestUtilities.createRequestBody;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {WalletCredentialsController.class, GlobalExceptionHandler.class})
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class WalletCredentialsControllerTest {

    @MockBean
    private WalletCredentialService walletCredentialService;

    @MockBean
    private DPoPSessionService dPoPSessionService;

    @MockBean
    private PkceSessionManager pkceSessionManager;

    @Mock
    private HttpSession httpSession;

    @Autowired
    private MockMvc mockMvc;

    private VerifiableCredentialResponseDTO verifiableCredentialResponseDTO;
    private WalletCredentialResponseDTO walletCredentialResponseDTO;
    private final String walletId = "wallet123";
    private final String credentialId = "cred456";
    private final String walletKey = "encodedKey";
    private final String issuer = "issuer1";
    private final String credentialConfigurationId = "type1";
    private final String code = "code";
    private final String locale = "en";
    private final String state = "oauth-state";
    VerifiableCredentialRequestDTO verifiableCredentialRequest;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        verifiableCredentialRequest = new VerifiableCredentialRequestDTO();

        verifiableCredentialResponseDTO = VerifiableCredentialResponseDTO.builder()
                .issuerDisplayName("issuerName123")
                .issuerLogo("issuerLogo")
                .credentialTypeDisplayName("credentialType123")
                .credentialTypeLogo("credentialTypeLogo")
                .credentialId("credentialId123")
                .build();

        walletCredentialResponseDTO = new WalletCredentialResponseDTO();
        walletCredentialResponseDTO.setFileName("credential.pdf");
        walletCredentialResponseDTO.setFileContentStream(new InputStreamResource(new ByteArrayInputStream("test-pdf".getBytes())));

        when(httpSession.getAttribute("wallet_id")).thenReturn(walletId);
        when(httpSession.getAttribute("wallet_key")).thenReturn(walletKey);
    }

    // Tests for downloadCredential
    @Test
    public void shouldDownloadCredentialSuccessfully() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);
        when(walletCredentialService.downloadVCAndStoreInDB(
                eq(issuer), eq(credentialConfigurationId), eq(locale), eq(walletId), eq(walletKey),
                eq(code), eq(state), any()))
                .thenReturn(verifiableCredentialResponseDTO);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuerDisplayName").value("issuerName123"))
                .andExpect(jsonPath("$.issuerLogo").value("issuerLogo"))
                .andExpect(jsonPath("$.credentialTypeDisplayName").value("credentialType123"))
                .andExpect(jsonPath("$.credentialTypeLogo").value("credentialTypeLogo"))
                .andExpect(jsonPath("$.credentialId").value("credentialId123"));
    }

    @Test
    public void should_exchangeTokenInternally_when_dPoPSessionAndGrantAreProvided() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);
        when(walletCredentialService.downloadVCAndStoreInDB(
                eq(issuer), eq(credentialConfigurationId), eq(locale), eq(walletId), eq(walletKey),
                eq(code), eq(state), any()))
                .thenReturn(verifiableCredentialResponseDTO);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentialId").value("credentialId123"));

        verify(walletCredentialService).downloadVCAndStoreInDB(
                eq(issuer), eq(credentialConfigurationId), eq(locale), eq(walletId), eq(walletKey),
                eq(code), eq(state), any());
        verify(dPoPSessionService).remove(any(), eq("oauth-state"));
        verify(pkceSessionManager).remove(any(), eq("oauth-state"));
    }

    @Test
    public void should_returnErrorResponse_when_requestedCredentialAlreadyExistsInWallet() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);
        when(walletCredentialService.downloadVCAndStoreInDB(
                eq(issuer), eq(credentialConfigurationId), eq(locale), eq(walletId), eq(walletKey),
                eq(code), eq(state), any()))
                .thenThrow(new InvalidRequestException(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), "Duplicate credential for issuer and type"));

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("credential_download_error"))
                .andExpect(jsonPath("$.errorMessage").value("Duplicate credential for issuer and type"));
        verify(dPoPSessionService).remove(any(), eq(state));
        verify(pkceSessionManager).remove(any(), eq(state));
    }

    @Test
    public void shouldReturnErrorResponseWhenSessionDoesNotHaveWalletIdAndKey() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("wallet_locked"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet is locked"));
    }

    @Test
    public void shouldCallServiceWithCorrectParameters() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .header("Accept-Language", "fr")
                .header("state", state)
                .content(createRequestBody(verifiableCredentialRequest))
                .sessionAttr("wallet_id", walletId)
                .sessionAttr("wallet_key", walletKey));

        verify(walletCredentialService).downloadVCAndStoreInDB(
                eq(issuer), eq(credentialConfigurationId), eq("fr"), eq(walletId), eq(walletKey),
                eq(code), eq(state), any());
    }

    @Test
    public void shouldSetDefaultAndProceedWhenOptionalRequestParametersAreNotPassed() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .header("state", state)
                .content(createRequestBody(verifiableCredentialRequest))
                .sessionAttr("wallet_id", walletId)
                .sessionAttr("wallet_key", walletKey));

        // Default value for vcStorageExpiryLimit is -1 and locale is "en"
        verify(walletCredentialService).downloadVCAndStoreInDB(
                any(), any(), eq("en"), eq(walletId), eq(walletKey), eq(code), eq(state), any());
    }

    @Test
    public void shouldThrowExceptionWhenInvalidLocaleIsPassed() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", "eng") // Three letter language code passed which is not valid
                        .header("Accept-Language", "invalid")
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Locale must be a 2-letter code"));
    }

    @Test
    public void shouldThrowInvalidRequestForWalletIdMismatch() throws Exception {
        when(httpSession.getAttribute("wallet_id")).thenReturn("differentWalletId");
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", "differentWalletId")
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Invalid Wallet ID. Session and request Wallet ID do not match"));
    }

    @Test
    public void shouldThrowInvalidRequestForMissingWalletKey() throws Exception {
        when(httpSession.getAttribute("wallet_key")).thenReturn(null);
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet key not found in session"));
    }

    @Test
    public void shouldThrowInvalidRequestForMissingIssuerAndCredentialConfigurationIdInDownloadCredentialApi() throws Exception {
        buildVerifiableCredentialRequest(null, null, code);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", "fr")
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(result -> {
                    String errorMessage = JsonPath.read(result.getResponse().getContentAsString(), "$.errorMessage");
                    String[] messages = errorMessage.split(",\\s*");

                    assertEquals(2, messages.length);
                    assertThat(messages).anySatisfy(msg ->
                            assertThat(msg.trim()).isEqualTo("issuerId cannot be blank"));
                    assertThat(messages).anySatisfy(msg ->
                            assertThat(msg.trim()).isEqualTo("credentialConfigurationId cannot be blank"));
                });
    }

    @Test
    public void shouldThrowInvalidRequestForMissingIssuerInDownloadCredentialApi() throws Exception {
        buildVerifiableCredentialRequest(null, credentialConfigurationId, code);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .header("Accept-Language", "fr")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("issuerId cannot be blank"));
    }

    @Test
    public void shouldThrowInvalidRequestForMissingCredentialConfigurationIdInDownloadCredentialApi() throws Exception {
        buildVerifiableCredentialRequest(issuer, null, code);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .header("Accept-Language", "fr")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("credentialConfigurationId cannot be blank"));
    }

    @Test
    public void shouldThrowInvalidRequestForMissingCodeInDownloadCredentialApi() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, null);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .header("Accept-Language", "fr")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("code cannot be blank"));
    }

    @Test
    public void shouldThrowServiceUnavailableForTokenResponseFailure() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);
        when(walletCredentialService.downloadVCAndStoreInDB(
                eq(issuer), eq(credentialConfigurationId), anyString(), eq(walletId), eq(walletKey),
                eq(code), eq(state), any()))
                .thenThrow(new ApiNotAccessibleException("API not accessible"));

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.errorCode").value("credential_download_error"));
        verify(dPoPSessionService).remove(any(), eq(state));
        verify(pkceSessionManager).remove(any(), eq(state));
    }

    @Test
    public void shouldThrowServiceUnavailableForExternalServiceFailure() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);
        when(walletCredentialService.downloadVCAndStoreInDB(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), any()))
                .thenThrow(new ExternalServiceUnavailableException("Service unavailable", "Service unavailable"));

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.errorCode").value("Service unavailable"))
                .andExpect(jsonPath("$.errorMessage").value("Service unavailable"));
        verify(dPoPSessionService).remove(any(), eq(state));
        verify(pkceSessionManager).remove(any(), eq(state));
    }

    @Test
    public void shouldThrowInternalServerErrorForCredentialProcessingFailure() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);
        when(walletCredentialService.downloadVCAndStoreInDB(
                eq(issuer), eq(credentialConfigurationId), anyString(), eq(walletId), eq(walletKey),
                eq(code), eq(state), any()))
                .thenThrow(new CredentialProcessingException(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(),
                        "Unable to process credential"));

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("credential_download_error"))
                .andExpect(jsonPath("$.errorMessage").value("Unable to process credential"));
        verify(dPoPSessionService).remove(any(), eq(state));
        verify(pkceSessionManager).remove(any(), eq(state));
    }

    // Tests for fetchAllCredentialsForGivenWallet

    @Test
    public void shouldFetchAllCredentialsSuccessfully() throws Exception {
        List<VerifiableCredentialResponseDTO> credentials = Collections.singletonList(verifiableCredentialResponseDTO);
        when(walletCredentialService.fetchAllCredentialsForWallet(walletId, walletKey, locale)).thenReturn(credentials);

        mockMvc.perform(get("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].issuerDisplayName").value("issuerName123"))
                .andExpect(jsonPath("$[0].issuerLogo").value("issuerLogo"))
                .andExpect(jsonPath("$[0].credentialTypeDisplayName").value("credentialType123"))
                .andExpect(jsonPath("$[0].credentialId").value("credentialId123"))
                .andExpect(jsonPath("$[0].credentialTypeLogo").value("credentialTypeLogo"));
    }

    @Test
    public void shouldThrowInvalidRequestForInvalidLocale() throws Exception {
        mockMvc.perform(get("/wallets/{walletId}/credentials", walletId)
                        .header("Accept-Language", "invalid")
                        .param("issuer", issuer)
                        .param("credentialConfigurationId", credentialConfigurationId)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest());
    }

    @Test
    public void shouldReturnErrorResponseOnFetchAllCredentialsForGivenWalletWhenSessionDoesNotHaveWalletId() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);
        mockMvc.perform(get("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .sessionAttr("wallet_key", walletKey)
                        .content(createRequestBody(verifiableCredentialRequest))
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("wallet_locked"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet is locked"));
    }

    @Test
    public void shouldThrowInvalidRequestForMissingWalletKeyInFetchAll() throws Exception {
        when(httpSession.getAttribute("wallet_key")).thenReturn(null);

        mockMvc.perform(get("/wallets/{walletId}/credentials", walletId)
                        .header("Accept-Language", locale)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet key not found in session"));
    }

    @Test
    public void shouldThrowInvalidRequestForWalletIdMismatchInFetchAll() throws Exception {
        when(httpSession.getAttribute("wallet_id")).thenReturn("differentWalletId");

        mockMvc.perform(get("/wallets/{walletId}/credentials", walletId)
                        .header("Accept-Language", locale)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", "differentWalletId")
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Invalid Wallet ID. Session and request Wallet ID do not match"));
    }

    // Tests for getVerifiableCredential
    @Test
    public void shouldFetchVerifiableCredentialAsPdfSuccessfullyInline() throws Exception {
        when(walletCredentialService.fetchVerifiableCredential(walletId, credentialId, walletKey, locale))
                .thenReturn(walletCredentialResponseDTO);

        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_PDF)
                        .header("Accept-Language", locale)
                        .param("action", "inline")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "inline; filename=\"credential.pdf\""))
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));
    }

    @Test
    public void shouldFetchVerifiableCredentialAsDownload() throws Exception {
        when(walletCredentialService.fetchVerifiableCredential(walletId, credentialId, walletKey, locale))
                .thenReturn(walletCredentialResponseDTO);

        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_PDF)
                        .header("Accept-Language", locale)
                        .param("action", "download")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"credential.pdf\""))
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));
    }

    @Test
    public void shouldThrowInvalidRequestForInvalidAcceptHeader() throws Exception {
        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .header("Accept-Language", locale)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Accept header must be application/pdf"));
    }

    @Test
    public void shouldReturnErrorResponseOnGetVerifiableCredentialWhenSessionDoesNotHaveWalletId() throws Exception {
        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .header("Accept-Language", locale)
                        .accept(MediaType.APPLICATION_PDF)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("wallet_locked"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet is locked"));
    }

    @Test
    public void shouldReturnErrorResponseOnGetVerifiableCredentialWhenSessionDoesNotHaveWalletKey() throws Exception {
        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .header("Accept-Language", locale)
                        .accept(MediaType.APPLICATION_PDF)
                        .sessionAttr("wallet_id", walletId))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet key not found in session"));
    }

    @Test
    public void shouldThrowInvalidRequestForInvalidAction() throws Exception {
        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .param("action", "invalid")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest());
    }

    @Test
    public void shouldThrowCredentialNotFoundException() throws Exception {
        when(walletCredentialService.fetchVerifiableCredential(walletId, credentialId, walletKey, locale))
                .thenThrow(new CredentialNotFoundException(RESOURCE_NOT_FOUND.getErrorCode(), RESOURCE_NOT_FOUND.getErrorMessage()));

        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_PDF)
                        .header("Accept-Language", locale)
                        .param("action", "inline")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value("resource_not_found"))
                .andExpect(jsonPath("$.errorMessage").value("The requested resource doesn’t exist."));
    }

    @Test
    public void shouldThrowInvalidRequestForMissingCredentialId() throws Exception {
        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, ""))
                .andExpect(status().isNotFound());
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionForDecryptionError() throws Exception {
        when(walletCredentialService.fetchVerifiableCredential(walletId, credentialId, walletKey, locale))
                .thenThrow(new CredentialProcessingException(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), "Decryption failed"));

        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_PDF)
                        .header("Accept-Language", locale)
                        .param("action", "inline")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("credential_fetch_error"))
                .andExpect(jsonPath("$.errorMessage").value("Decryption failed"));
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionForCorruptedData() throws Exception {
        when(walletCredentialService.fetchVerifiableCredential(walletId, credentialId, walletKey, locale))
                .thenThrow(new CredentialProcessingException(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), "CORRUPTED_DATA"));

        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_PDF)
                        .header("Accept-Language", locale)
                        .param("action", "inline")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value(CREDENTIAL_FETCH_EXCEPTION.getErrorCode()))
                .andExpect(jsonPath("$.errorMessage").value("CORRUPTED_DATA"));
    }

    // Tests for deleteCredential
    @Test
    public void shouldDeleteCredentialSuccessfully() throws Exception {
        mockMvc.perform(delete("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk());
    }

    @Test
    public void shouldReturnErrorResponseOnDeleteCredentialWhenSessionDoesNotHaveWalletId() throws Exception {
        mockMvc.perform(delete("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("wallet_locked"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet is locked"));
    }

    @Test
    public void shouldThrowCredentialNotFoundExceptionWhenDeletingNonExistentCredential() throws Exception {
        doThrow(new CredentialNotFoundException(RESOURCE_NOT_FOUND.getErrorCode(), RESOURCE_NOT_FOUND.getErrorMessage()))
                .when(walletCredentialService).deleteCredential(credentialId, walletId);

        mockMvc.perform(delete("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value("resource_not_found"))
                .andExpect(jsonPath("$.errorMessage").value("The requested resource doesn’t exist."));
    }

    @Test
    public void shouldThrowInvalidRequestForWalletIdMismatchInDeleteCredential() throws Exception {
        when(httpSession.getAttribute("wallet_id")).thenReturn("differentWalletId");

        mockMvc.perform(delete("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", "differentWalletId")
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Invalid Wallet ID. Session and request Wallet ID do not match"));
    }

    @Test
    public void should_rejectDownload_when_clientSendsAccessTokenWithoutDPoPSession() throws Exception {
        verifiableCredentialRequest.setIssuer(issuer);
        verifiableCredentialRequest.setCredentialConfigurationId(credentialConfigurationId);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .header("DPoP", "dpop-proof-jwt")
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"));

        verify(walletCredentialService, never()).downloadVCAndStoreInDB(
                any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    public void should_retryInternally_when_walletCredentialDownloadRequiresNonce() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);
        when(walletCredentialService.downloadVCAndStoreInDB(
                eq(issuer), eq(credentialConfigurationId), eq(locale), eq(walletId), eq(walletKey),
                eq(code), eq(state), any()))
                .thenReturn(verifiableCredentialResponseDTO);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentialId").value("credentialId123"));

        verify(dPoPSessionService).remove(any(), eq(state));
        verify(pkceSessionManager).remove(any(), eq(state));
    }

    private void buildVerifiableCredentialRequest(String issuer, String credentialConfigurationId, String code) {
        verifiableCredentialRequest.setIssuer(issuer);
        verifiableCredentialRequest.setCredentialConfigurationId(credentialConfigurationId);
        verifiableCredentialRequest.setCode(code);
    }

    @Test
    public void shouldThrowInvalidRequestForInvalidLocaleCode() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code);

        // "zz" is not a valid ISO 639-1 language code
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", "zz")
                        .header("state", state)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Locale must be a valid 2-letter code"));
    }
}