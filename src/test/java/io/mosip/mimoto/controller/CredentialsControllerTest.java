package io.mosip.mimoto.controller;

import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.IdpException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.service.DPoPSessionService;
import io.mosip.mimoto.service.PkceSessionManager;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.util.GlobalExceptionHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.ByteArrayInputStream;
import java.util.List;

import static io.mosip.mimoto.exception.ErrorConstants.INTERNAL_SERVER_ERROR;
import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
    private DPoPSessionService dPoPSessionService;

    @MockBean
    private PkceSessionManager pkceSessionManager;

    private String locale = "test-local", issuer = "test-issuer", credential = "test-credential", requestContent;

    @Before
    public void setUp() throws Exception {
        requestContent = EntityUtils.toString(new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair("code", "test-code"),
                new BasicNameValuePair("issuer", issuer),
                new BasicNameValuePair("vcStorageExpiryLimitInTimes", "3"),
                new BasicNameValuePair("credential", credential),
                new BasicNameValuePair("locale", locale)
        )));
    }

    @Test
    public void should_downloadPdf_when_dPoPSessionIsValid() throws Exception {
        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(
                        eq(issuer), eq(credential), eq("3"), eq(locale), eq("test-code"), eq("oauth-state"), any()))
                .thenReturn(new ByteArrayInputStream("test-data".getBytes()));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header("state", "oauth-state")
                        .content(requestContent))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));

        verify(credentialService).downloadCredentialAsPDF(
                eq(issuer), eq(credential), eq("3"), eq(locale), eq("test-code"), eq("oauth-state"), any());
        verify(dPoPSessionService).remove(any(), eq("oauth-state"));
        verify(pkceSessionManager).remove(any(), eq("oauth-state"));
    }

    @Test
    public void should_rejectDownload_when_clientSendsAccessTokenWithoutDPoPSession() throws Exception {
        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(
                        eq(issuer), eq(credential), eq("3"), eq(locale), isNull(), isNull(), any()))
                .thenThrow(new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "DPoP state is required"));

        String preIssuedContent = EntityUtils.toString(new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair("issuer", issuer),
                new BasicNameValuePair("credential", credential),
                new BasicNameValuePair("locale", locale),
                new BasicNameValuePair("vcStorageExpiryLimitInTimes", "3"),
                new BasicNameValuePair("access_token", "pre-issued-token"),
                new BasicNameValuePair("token_type", "DPoP")
        )));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(preIssuedContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("DPoP state is required")));

        verify(credentialService).downloadCredentialAsPDF(
                eq(issuer), eq(credential), eq("3"), eq(locale), isNull(), isNull(), any());
        verify(dPoPSessionService).remove(any(), isNull());
        verify(pkceSessionManager).remove(any(), isNull());
    }

    @Test
    public void throwExceptionOnFetchingTokenResponseFailure() throws Exception {
        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(
                        eq(issuer), eq(credential), eq("3"), eq(locale), eq("test-code"), eq("oauth-state"), any()))
                .thenThrow(new IdpException("Exception occurred while performing the authorization"));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("state", "oauth-state")
                        .content(requestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode", Matchers.is(INTERNAL_SERVER_ERROR.getErrorCode())))
                .andExpect(jsonPath("$.errorMessage", Matchers.is(INTERNAL_SERVER_ERROR.getErrorMessage())));
        verify(dPoPSessionService).remove(any(), eq("oauth-state"));
        verify(pkceSessionManager).remove(any(), eq("oauth-state"));
    }

    @Test
    public void throwExceptionOnFetchingIssuerOrAuthServerWellknownFailureDuringTokenGeneration() throws Exception {
        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(
                        eq(issuer), eq(credential), eq("3"), eq(locale), eq("test-code"), eq("oauth-state"), any()))
                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("state", "oauth-state")
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("RESIDENT-APP-026")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Api not accessible failure")));
    }

    @Test
    public void throwExceptionWhenPDFGenerationFailed() throws Exception {
        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(
                        eq(issuer), eq(credential), eq("3"), eq(locale), eq("test-code"), eq("oauth-state"), any()))
                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("state", "oauth-state")
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("RESIDENT-APP-026")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Api not accessible failure")));
        verify(dPoPSessionService).remove(any(), eq("oauth-state"));
        verify(pkceSessionManager).remove(any(), eq("oauth-state"));
    }

    @Test
    public void throwExceptionOnInvalidCredentialResource() throws Exception {
        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(
                        eq(issuer), eq(credential), eq("3"), eq(locale), eq("test-code"), eq("oauth-state"), any()))
                .thenThrow(new InvalidCredentialResourceException(
                        ErrorConstants.REQUEST_TIMED_OUT.getErrorCode(),
                        ErrorConstants.REQUEST_TIMED_OUT.getErrorMessage()));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("state", "oauth-state")
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("request_timed_out")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("We are unable to process your request right now")));
    }

    @Test
    public void throwExceptionOnVCVerificationFailure() throws Exception {
        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(
                        eq(issuer), eq(credential), eq("3"), eq(locale), eq("test-code"), eq("oauth-state"), any()))
                .thenThrow(new VCVerificationException("Verification Failed!", "Error occurred when verifying the downloaded credential"));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("state", "oauth-state")
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("Verification Failed!")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Error occurred when verifying the downloaded credential")));
    }
}
