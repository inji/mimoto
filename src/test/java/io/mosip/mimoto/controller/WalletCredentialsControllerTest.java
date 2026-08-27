package io.mosip.mimoto.controller;

import com.jayway.jsonpath.JsonPath;
import io.mosip.mimoto.dto.VerifiableCredentialRequestDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.IdpService;
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
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import org.springframework.http.HttpHeaders;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {WalletCredentialsController.class, GlobalExceptionHandler.class})
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class WalletCredentialsControllerTest {

    @MockBean
    private WalletCredentialService walletCredentialService;

    @MockBean
    private IdpService idpService;

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
    private final String grantType = "authorization-code";
    private final String redirectUri = "https://.../redirect";
    private final String codeVerifier = "code-verifier";
    private final String locale = "en";
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
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, redirectUri, codeVerifier);
        when(idpService.getTokenResponse(verifiableCredentialRequest)).thenReturn(new TokenResponseDTO());
        when(walletCredentialService.downloadVCAndStoreInDB(eq(issuer), eq(credentialConfigurationId), any(), eq(locale), eq(walletId), eq(walletKey), nullable(String.class)))
                .thenReturn(verifiableCredentialResponseDTO);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
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
    public void shouldReturnErroResponseWhenRequestedCredentialIsAlreadyAvailableInWallet() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, redirectUri, codeVerifier);
        when(idpService.getTokenResponse(verifiableCredentialRequest)).thenReturn(new TokenResponseDTO());
        when(walletCredentialService.downloadVCAndStoreInDB(eq(issuer), eq(credentialConfigurationId), any(), eq(locale), eq(walletId), eq(walletKey), nullable(String.class)))
                .thenThrow(new InvalidRequestException(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), "Duplicate credential for issuer and type"));

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("credential_download_error"))
                .andExpect(jsonPath("$.errorMessage").value("Duplicate credential for issuer and type"));
    }

    @Test
    public void shouldReturnErrorResponseWhenSessionDoesNotHaveWalletIdAndKey() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, redirectUri, codeVerifier);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .content(createRequestBody(verifiableCredentialRequest))
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("wallet_locked"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet is locked"));
    }

    @Test
    public void shouldCallServiceWithCorrectParameters() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, redirectUri, codeVerifier);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .header("Accept-Language", "fr")
                .content(createRequestBody(verifiableCredentialRequest))
                .sessionAttr("wallet_id", walletId)
                .sessionAttr("wallet_key", walletKey));

        verify(idpService).getTokenResponse(verifiableCredentialRequest);
        verify(walletCredentialService
        ).downloadVCAndStoreInDB(eq(issuer), eq(credentialConfigurationId), any(), eq("fr"), eq(walletId), eq(walletKey), nullable(String.class));
    }

    @Test
    public void shouldSetDefaultAndProceedWhenOptionalRequestParametersAreNotPassed() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, redirectUri, codeVerifier);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(createRequestBody(verifiableCredentialRequest))
                .sessionAttr("wallet_id", walletId)
                .sessionAttr("wallet_key", walletKey));

        // Default value for vcStorageExpiryLimit is -1 and locale is "en"
        verify(walletCredentialService).downloadVCAndStoreInDB(any(), any(), any(), eq("en"), eq(walletId), eq(walletKey), nullable(String.class));
    }

    @Test
    public void shouldThrowExceptionWhenInvalidLocaleIsPassed() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, redirectUri, codeVerifier);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", "eng") // Three letter language code passed which is not valid
                        .header("Accept-Language", "invalid")
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
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, redirectUri, codeVerifier);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
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
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, redirectUri, codeVerifier);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet key not found in session"));
    }

    @Test
    public void shouldThrowInvalidRequestForMissingIssuerAndCredentialConfigurationIdInDownloadCredentialApi() throws Exception {
        buildVerifiableCredentialRequest(null, null, code, grantType, redirectUri, codeVerifier);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", "fr")
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
        buildVerifiableCredentialRequest(null, credentialConfigurationId, code, grantType, redirectUri, codeVerifier);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
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
        buildVerifiableCredentialRequest(issuer, null, code, grantType, redirectUri, codeVerifier);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
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
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, null, grantType, redirectUri, codeVerifier);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .header("Accept-Language", "fr")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value(
                        "Either accessToken or authorization code grant (code, grantType, redirectUri, codeVerifier) must be provided"));
    }

    @Test
    public void shouldThrowInvalidRequestForMissingGrantTypeInDownloadCredentialApi() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, null, redirectUri, codeVerifier);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .header("Accept-Language", "fr")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value(
                        "Either accessToken or authorization code grant (code, grantType, redirectUri, codeVerifier) must be provided"));
    }

    @Test
    public void shouldThrowInvalidRequestForMissingRedirectUriInDownloadCredentialApi() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, null, codeVerifier);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .header("Accept-Language", "fr")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value(
                        "Either accessToken or authorization code grant (code, grantType, redirectUri, codeVerifier) must be provided"));
    }

    @Test
    public void shouldThrowInvalidRequestForMissingCodeVerifierInDownloadCredentialApi() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, redirectUri, null);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .header("Accept-Language", "fr")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value(
                        "Either accessToken or authorization code grant (code, grantType, redirectUri, codeVerifier) must be provided"));
    }

    @Test
    public void shouldThrowServiceUnavailableForTokenResponseFailure() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, redirectUri, codeVerifier);
        when(idpService.getTokenResponse(verifiableCredentialRequest))
                .thenThrow(new ApiNotAccessibleException("API not accessible"));

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.errorCode").value("credential_download_error"));
    }

    @Test
    public void shouldThrowServiceUnavailableForExternalServiceFailure() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, redirectUri, codeVerifier);
        when(idpService.getTokenResponse(anyMap())).thenReturn(new TokenResponseDTO());
        when(walletCredentialService.downloadVCAndStoreInDB(anyString(), anyString(), any(), anyString(), anyString(), anyString(), nullable(String.class)))
                .thenThrow(new ExternalServiceUnavailableException("Service unavailable", "Service unavailable"));

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.errorCode").value("Service unavailable"))
                .andExpect(jsonPath("$.errorMessage").value("Service unavailable"));
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
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, redirectUri, codeVerifier);
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
    public void should_downloadCredentialUsingPreIssuedDpopToken_when_tokenExchangeIsNotRequired() throws Exception {
        verifiableCredentialRequest.setIssuer(issuer);
        verifiableCredentialRequest.setCredentialConfigurationId(credentialConfigurationId);
        verifiableCredentialRequest.setAccessToken("pre-issued-access-token");
        verifiableCredentialRequest.setTokenType("DPoP");
        verifiableCredentialRequest.setCNonce("c-nonce-value");

        when(walletCredentialService.downloadVCAndStoreInDB(
                eq(issuer), eq(credentialConfigurationId), any(TokenResponseDTO.class),
                eq(locale), eq(walletId), eq(walletKey), eq("dpop-proof-jwt")))
                .thenReturn(verifiableCredentialResponseDTO);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .header("DPoP", "dpop-proof-jwt")
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentialId").value("credentialId123"));

        verify(idpService, never()).getTokenResponse(any(VerifiableCredentialRequestDTO.class));
        verify(walletCredentialService).downloadVCAndStoreInDB(
                eq(issuer), eq(credentialConfigurationId),
                argThat(token -> "pre-issued-access-token".equals(token.getAccess_token())
                        && "DPoP".equals(token.getToken_type())
                        && "c-nonce-value".equals(token.getC_nonce())),
                eq(locale), eq(walletId), eq(walletKey), eq("dpop-proof-jwt"));
    }

    @Test
    public void should_returnDpopNonceChallengeToClient_when_walletCredentialDownloadRequiresNonce() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, redirectUri, codeVerifier);
        when(idpService.getTokenResponse(verifiableCredentialRequest)).thenReturn(new TokenResponseDTO());

        HttpHeaders challengeHeaders = new HttpHeaders();
        challengeHeaders.set("DPoP-Nonce", "wallet-issuer-nonce");
        challengeHeaders.set("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"");
        when(walletCredentialService.downloadVCAndStoreInDB(
                eq(issuer), eq(credentialConfigurationId), any(), eq(locale), eq(walletId), eq(walletKey), eq("stale-proof")))
                .thenThrow(new DpopChallengeException(
                        org.springframework.http.HttpStatus.UNAUTHORIZED,
                        challengeHeaders,
                        "{\"error\":\"use_dpop_nonce\"}"));

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .header("DPoP", "stale-proof")
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("DPoP-Nonce", "wallet-issuer-nonce"))
                .andExpect(jsonPath("$.error").value("use_dpop_nonce"));
    }

    private void buildVerifiableCredentialRequest(String issuer, String credentialConfigurationId, String code, String grantType, String redirectUri, String codeVerifier) {
        verifiableCredentialRequest.setIssuer(issuer);
        verifiableCredentialRequest.setCredentialConfigurationId(credentialConfigurationId);
        verifiableCredentialRequest.setCode(code);
        verifiableCredentialRequest.setGrantType(grantType);
        verifiableCredentialRequest.setRedirectUri(redirectUri);
        verifiableCredentialRequest.setCodeVerifier(codeVerifier);
    }

    @Test
    public void shouldThrowInvalidRequestForInvalidLocaleCode() throws Exception {
        buildVerifiableCredentialRequest(issuer, credentialConfigurationId, code, grantType, redirectUri, codeVerifier);

        // "zz" is not a valid ISO 639-1 language code
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", "zz")
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Locale must be a valid 2-letter code"));
    }
}