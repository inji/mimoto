package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.dpop.DpopIssuanceSession;
import io.mosip.mimoto.dto.dpop.IssuerAuthorizeRequest;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.exception.InvalidRequestException;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;

import java.util.List;

import static io.mosip.mimoto.util.TestUtilities.getCredentialIssuerConfigurationResponseDto;
import static io.mosip.mimoto.util.TestUtilities.getIssuerDTO;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DpopIssuanceSessionServiceAuthorizeTest {

    @Test
    public void shouldBuildAuthorizationUrlWithSessionJkt() throws Exception {
        IssuersService issuersService = mock(IssuersService.class);
        DpopProofService dpopProofService = mock(DpopProofService.class);
        DpopIssuanceSessionService service = new DpopIssuanceSessionService(issuersService, dpopProofService);

        CredentialIssuerConfiguration configuration =
                getCredentialIssuerConfigurationResponseDto("LocalMock", "CredentialType1", List.of());
        IssuerDTO issuer = getIssuerDTO("LocalMock");
        DpopIssuanceSession issuanceSession = DpopIssuanceSession.builder()
                .state("oauth-state")
                .jkt("thumbprint")
                .build();

        when(issuersService.getIssuerConfiguration("LocalMockid")).thenReturn(configuration);
        when(issuersService.getIssuerDetails("LocalMockid")).thenReturn(issuer);
        when(dpopProofService.selectAlgorithm(any())).thenReturn("ES256");
        when(dpopProofService.createSession(eq("oauth-state"), eq("LocalMockid"), eq("ES256"), any(), any()))
                .thenReturn(issuanceSession);

        IssuerAuthorizeRequest request = new IssuerAuthorizeRequest();
        request.setCodeChallenge("challenge");
        request.setCodeChallengeMethod("S256");
        request.setRedirectUri("https://injiweb.example.com/redirect");
        request.setScope("openid MockVerifiableCredential");
        request.setResponseType("code");
        request.setUiLocales("en");

        String url = service.createAuthorizationUrl(new MockHttpSession(), "LocalMockid", "oauth-state", request);

        assertTrue(url.startsWith("https://dev/authorize?"));
        assertTrue(url.contains("client_id=123"));
        assertTrue(url.contains("dpop_jkt=thumbprint"));
        assertTrue(url.contains("code_challenge=challenge"));
        assertTrue(url.contains("code_challenge_method=S256"));
        assertTrue(url.contains("response_type=code"));
        assertTrue(url.contains("ui_locales=en"));
    }

    @Test
    public void shouldRejectMissingClientId() throws Exception {
        IssuersService issuersService = mock(IssuersService.class);
        DpopProofService dpopProofService = mock(DpopProofService.class);
        DpopIssuanceSessionService service = new DpopIssuanceSessionService(issuersService, dpopProofService);

        CredentialIssuerConfiguration configuration =
                getCredentialIssuerConfigurationResponseDto("LocalMock", "CredentialType1", List.of());
        IssuerDTO issuer = getIssuerDTO("LocalMock");
        issuer.setClient_id(" ");
        DpopIssuanceSession issuanceSession = DpopIssuanceSession.builder()
                .state("oauth-state")
                .jkt("thumbprint")
                .build();

        when(issuersService.getIssuerConfiguration("LocalMockid")).thenReturn(configuration);
        when(issuersService.getIssuerDetails("LocalMockid")).thenReturn(issuer);
        when(dpopProofService.selectAlgorithm(any())).thenReturn("ES256");
        when(dpopProofService.createSession(any(), any(), any(), any(), any())).thenReturn(issuanceSession);

        IssuerAuthorizeRequest request = new IssuerAuthorizeRequest();
        request.setCodeChallenge("challenge");
        request.setCodeChallengeMethod("S256");
        request.setRedirectUri("https://injiweb.example.com/redirect");
        request.setScope("openid");
        request.setResponseType("code");
        request.setUiLocales("en");

        assertThrows(InvalidRequestException.class,
                () -> service.createAuthorizationUrl(new MockHttpSession(), "LocalMockid", "oauth-state", request));
    }
}
