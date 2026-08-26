package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.DpopConstants;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.util.GlobalExceptionHandler;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.util.TestUtilities;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.ByteArrayInputStream;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {CredentialsController.class, GlobalExceptionHandler.class})
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class CredentialsControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CredentialServiceImpl credentialService;

    @MockBean
    private IdpService idpService;

    private String locale = "test-local", issuer = "test-issuer", credential = "test-credential", requestContent;
    private TokenResponseDTO tokenResponseDTO;

    @Before
    public void setUp() throws Exception {
        tokenResponseDTO = TestUtilities.getTokenResponseDTO();
        Mockito.when(idpService.getTokenResponse(Mockito.anyMap())).thenReturn(tokenResponseDTO);
        requestContent = EntityUtils.toString(new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair("grant_type", "authorization_code"),
                new BasicNameValuePair("code", "test-code"),
                new BasicNameValuePair("redirect_uri", "test-redirect_uri"),
                new BasicNameValuePair("code_verifier", "test-code_verifier"),
                new BasicNameValuePair("issuer", issuer),
                new BasicNameValuePair("vcStorageExpiryLimitInTimes", "3"),
                new BasicNameValuePair("credential", credential),
                new BasicNameValuePair("locale", locale)
        )));
    }

    @Test
    public void downloadPDFSuccessfully() throws Exception {
        Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale, null))
                .thenReturn(new ByteArrayInputStream("test-data".getBytes()));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(requestContent))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));
    }

    @Test
    public void downloadPDFSuccessfullyWithPreIssuedDpopToken() throws Exception {
        String dpopProof = "guest-dpop-proof";
        String preIssuedContent = EntityUtils.toString(new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair("issuer", issuer),
                new BasicNameValuePair("credential", credential),
                new BasicNameValuePair("locale", locale),
                new BasicNameValuePair("vcStorageExpiryLimitInTimes", "3"),
                new BasicNameValuePair("access_token", "pre-issued-token"),
                new BasicNameValuePair("token_type", "DPoP"),
                new BasicNameValuePair("c_nonce", "nonce-1")
        )));

        Mockito.when(credentialService.downloadCredentialAsPDF(
                        eq(issuer), eq(credential), any(TokenResponseDTO.class), eq("3"), eq(locale), eq(dpopProof)))
                .thenReturn(new ByteArrayInputStream("test-data".getBytes()));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(DpopConstants.DPOP_HEADER, dpopProof)
                        .content(preIssuedContent))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));

        verify(idpService, never()).getTokenResponse(anyMap());
        ArgumentCaptor<TokenResponseDTO> tokenCaptor = ArgumentCaptor.forClass(TokenResponseDTO.class);
        verify(credentialService).downloadCredentialAsPDF(
                eq(issuer), eq(credential), tokenCaptor.capture(), eq("3"), eq(locale), eq(dpopProof));
        assertEquals("pre-issued-token", tokenCaptor.getValue().getAccess_token());
        assertEquals("DPoP", tokenCaptor.getValue().getToken_type());
        assertEquals("nonce-1", tokenCaptor.getValue().getC_nonce());
    }

    @Test
    public void returnDpopNonceChallengeToClientWhenCredentialIssuerRequiresNonce() throws Exception {
        String dpopProof = "stale-dpop-proof";
        String preIssuedContent = EntityUtils.toString(new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair("issuer", issuer),
                new BasicNameValuePair("credential", credential),
                new BasicNameValuePair("locale", locale),
                new BasicNameValuePair("access_token", "pre-issued-token"),
                new BasicNameValuePair("token_type", "DPoP")
        )));

        HttpHeaders challengeHeaders = new HttpHeaders();
        challengeHeaders.set(DpopConstants.DPOP_NONCE_HEADER, "issuer-nonce-123");
        challengeHeaders.set(DpopConstants.WWW_AUTHENTICATE_HEADER, "DPoP error=\"use_dpop_nonce\"");
        Mockito.when(credentialService.downloadCredentialAsPDF(
                        eq(issuer), eq(credential), any(TokenResponseDTO.class), eq("-1"), eq(locale), eq(dpopProof)))
                .thenThrow(new DpopChallengeException(
                        HttpStatus.UNAUTHORIZED,
                        challengeHeaders,
                        "{\"error\":\"use_dpop_nonce\",\"error_description\":\"DPoP nonce required\"}"));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(DpopConstants.DPOP_HEADER, dpopProof)
                        .content(preIssuedContent))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(DpopConstants.DPOP_NONCE_HEADER, "issuer-nonce-123"))
                .andExpect(jsonPath("$.error").value("use_dpop_nonce"));

        verify(idpService, never()).getTokenResponse(anyMap());
    }

    @Test
    public void throwExceptionOnFetchingTokenResponseFailure() throws Exception {
        Mockito.when(idpService.getTokenResponse(Mockito.anyMap()))
                .thenThrow(new IdpException("Exception occurred while performing the authorization"));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode", Matchers.is("internal_server_error")))
                .andExpect(jsonPath("$.errorMessage", Matchers.is("We are unable to process request now")));

    }

    @Test
    public void throwExceptionOnFetchingIssuerOrAuthServerWellknownFailureDuringTokenGeneration() throws Exception {
        Mockito.when(idpService.getTokenResponse(Mockito.anyMap()))
                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("RESIDENT-APP-026")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Api not accessible failure")));
    }


    @Test
    public void throwExceptionWhenPDFGenerationFailed() throws Exception {
        Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale, null))
                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("RESIDENT-APP-026")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Api not accessible failure")));
    }

    @Test
    public void throwExceptionOnInvalidCredentialResource() throws Exception {
        Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale, null))
                .thenThrow(new InvalidCredentialResourceException(
                        ErrorConstants.REQUEST_TIMED_OUT.getErrorCode(),
                        ErrorConstants.REQUEST_TIMED_OUT.getErrorMessage()));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("request_timed_out")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("We are unable to process your request right now")));
    }

    @Test
    public void throwExceptionOnVCVerificationFailure() throws Exception {
        Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale, null))
                .thenThrow(new VCVerificationException("Verification Failed!", "Error occurred when verifying the downloaded credential"));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("Verification Failed!")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Error occurred when verifying the downloaded credential")));
    }
}
