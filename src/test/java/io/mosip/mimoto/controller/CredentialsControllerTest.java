package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.DpopConstants;
import io.mosip.mimoto.dto.dpop.DpopIssuanceSession;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.DpopIssuanceSessionService;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.util.GlobalExceptionHandler;
import io.mosip.mimoto.util.TestUtilities;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.ByteArrayInputStream;
import java.util.List;

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

    @MockBean
    private DpopIssuanceSessionService dpopIssuanceSessionService;
    private String locale = "test-local", issuer = "test-issuer", credential = "test-credential", requestContent;
    private TokenResponseDTO tokenResponseDTO;

    @Before
    public void setUp() throws Exception {
        tokenResponseDTO = TestUtilities.getTokenResponseDTO();
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
        stubBffSession();
    }

    private void stubBffSession() throws Exception {

        DpopIssuanceSession issuanceSession = DpopIssuanceSession.builder()

                .state("oauth-state")

                .issuerId(issuer)

                .alg("RS256")

                .build();

        org.mockito.Mockito.when(dpopIssuanceSessionService.find(any(), eq("oauth-state"))).thenReturn(issuanceSession);

        org.mockito.Mockito.when(idpService.exchangeAndBindToken(anyMap(), any())).thenReturn(tokenResponseDTO);

        org.mockito.Mockito.when(dpopIssuanceSessionService.credentialProof(any(), eq("oauth-state"))).thenReturn("server-dpop");

    }



    @Test
    public void downloadPDFSuccessfully() throws Exception {
        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale, "server-dpop"))

                .thenReturn(new ByteArrayInputStream("test-data".getBytes()));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header("state", "oauth-state")
                        .content(requestContent))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));
        verify(idpService).exchangeAndBindToken(anyMap(), any());
        verify(idpService, never()).getTokenResponse(anyMap());
        verify(dpopIssuanceSessionService).remove(any(), eq("oauth-state"));
    }

    @Test
    public void should_rejectDownload_when_clientSendsAccessTokenWithoutIssuanceSession() throws Exception {

        org.mockito.Mockito.reset(dpopIssuanceSessionService, idpService);

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
                        .header(DpopConstants.DPOP_HEADER, "guest-dpop-proof")

                        .content(preIssuedContent))

                .andExpect(status().isBadRequest())

                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Issuance state is required")));



        verify(idpService, never()).getTokenResponse(anyMap());

        verify(idpService, never()).exchangeAndBindToken(anyMap(), any());

        verify(credentialService, never()).downloadCredentialAsPDF(any(), any(), any(), any(), any(), any());

    }



    @Test

    public void should_exchangeTokenInternally_when_bffSessionAndGrantAreProvided() throws Exception {

        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(

                        eq(issuer), eq(credential), eq(tokenResponseDTO), eq("3"), eq(locale), eq("server-dpop")))

                .thenReturn(new ByteArrayInputStream("test-data".getBytes()));



        mockMvc.perform(post("/credentials/download")

                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)

                        .header("state", "oauth-state")
                        .content(requestContent))

                .andExpect(status().isOk())

                .andExpect(content().contentType(MediaType.APPLICATION_PDF));



        verify(idpService).exchangeAndBindToken(anyMap(), any());

        verify(idpService, never()).getTokenResponse(anyMap());

        verify(dpopIssuanceSessionService).remove(any(), eq("oauth-state"));

    }



    @Test

    public void should_retryInternally_when_credentialIssuerRequiresNonce() throws Exception {

        HttpHeaders challengeHeaders = new HttpHeaders();

        challengeHeaders.set(DpopConstants.DPOP_NONCE_HEADER, "issuer-nonce-123");

        challengeHeaders.set(DpopConstants.WWW_AUTHENTICATE_HEADER, "DPoP error=\"use_dpop_nonce\"");

        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(

                        eq(issuer), eq(credential), eq(tokenResponseDTO), eq("3"), eq(locale), eq("server-dpop")))

                .thenThrow(new DpopChallengeException(

                        HttpStatus.UNAUTHORIZED,

                        challengeHeaders,

                        "{\"error\":\"use_dpop_nonce\",\"error_description\":\"DPoP nonce required\"}"));

        org.mockito.Mockito.when(dpopIssuanceSessionService.retryCredentialProof(any(), eq("oauth-state"), any()))

                .thenReturn("retried-dpop");

        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(

                        eq(issuer), eq(credential), eq(tokenResponseDTO), eq("3"), eq(locale), eq("retried-dpop")))

                .thenReturn(new ByteArrayInputStream("test-data".getBytes()));



        mockMvc.perform(post("/credentials/download")

                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)

                        .header("state", "oauth-state")
                        .content(requestContent))

                .andExpect(status().isOk())

                .andExpect(content().contentType(MediaType.APPLICATION_PDF));



        verify(dpopIssuanceSessionService).retryCredentialProof(any(), eq("oauth-state"), any());

        verify(dpopIssuanceSessionService).remove(any(), eq("oauth-state"));

    }



    @Test

    public void throwExceptionOnFetchingTokenResponseFailure() throws Exception {

        org.mockito.Mockito.when(idpService.exchangeAndBindToken(anyMap(), any()))

                .thenThrow(new IdpException("Exception occurred while performing the authorization"));



        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("state", "oauth-state")
                        .content(requestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode", Matchers.is("internal_server_error")))
                .andExpect(jsonPath("$.errorMessage", Matchers.is("We are unable to process request now")));

    }

    @Test
    public void throwExceptionOnFetchingIssuerOrAuthServerWellknownFailureDuringTokenGeneration() throws Exception {

        org.mockito.Mockito.when(idpService.exchangeAndBindToken(anyMap(), any()))

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
    org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale, "server-dpop"))

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
    public void throwExceptionOnInvalidCredentialResource() throws Exception {
        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale, "server-dpop"))

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
        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale, "server-dpop"))

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
