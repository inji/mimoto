package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.dpop.DpopIssuanceSession;
import io.mosip.mimoto.dto.dpop.IssuerAuthorizeRequest;
import io.mosip.mimoto.dto.dpop.IssuerAuthorizeResponse;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.util.PkceUtil;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;

import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.util.TestUtilities.getCredentialIssuerConfigurationResponseDto;
import static io.mosip.mimoto.util.TestUtilities.getIssuerDTO;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DpopIssuanceSessionServiceAuthorizeTest {

    @Test
    public void shouldBuildAuthorizationUrlWithGeneratedPkceAndSessionJkt() throws Exception {
        DpopIssuanceSessionService service = serviceWithMocks();
        MockHttpSession httpSession = new MockHttpSession();

        IssuerAuthorizeResponse response = service.createAuthorizationUrl(httpSession, "LocalMockid", authorizeRequest());

        assertTrue(response.getAuthorizationUrl().startsWith("https://dev/authorize?"));
        assertTrue(response.getAuthorizationUrl().contains("client_id=123"));
        assertTrue(response.getAuthorizationUrl().contains("dpop_jkt=thumbprint"));
        assertTrue(response.getAuthorizationUrl().contains("code_challenge_method=S256"));
        assertTrue(response.getAuthorizationUrl().contains("code_challenge="));
        assertTrue(response.getAuthorizationUrl().contains("response_type=code"));
        assertTrue(response.getAuthorizationUrl().contains("ui_locales=en"));
        assertTrue(response.getAuthorizationUrl().contains("state=" + java.net.URLEncoder.encode(response.getState(), java.nio.charset.StandardCharsets.UTF_8)));
        assertEquals(43, response.getState().length());

        DpopIssuanceSession stored = service.find(httpSession, response.getState());
        assertNotNull(stored);
        assertEquals(43, stored.getCodeVerifier().length());
        assertEquals("https://injiweb.example.com/redirect", stored.getRedirectUri());
        assertTrue(response.getAuthorizationUrl().contains("code_challenge=" + PkceUtil.s256Challenge(stored.getCodeVerifier())));
    }

    @Test
    public void shouldInjectStoredPkceIntoAuthorizationCodeParams() throws Exception {
        DpopIssuanceSessionService service = serviceWithMocks();
        MockHttpSession httpSession = new MockHttpSession();
        IssuerAuthorizeResponse response = service.createAuthorizationUrl(httpSession, "LocalMockid", authorizeRequest());

        Map<String, String> params = service.authorizationCodeParams(httpSession, response.getState(), "auth-code", "LocalMockid");

        DpopIssuanceSession stored = service.find(httpSession, response.getState());
        assertEquals("auth-code", params.get("code"));
        assertEquals(stored.getCodeVerifier(), params.get("code_verifier"));
        assertEquals("https://injiweb.example.com/redirect", params.get("redirect_uri"));
        assertEquals("authorization_code", params.get("grant_type"));
        assertEquals("LocalMockid", params.get("issuer"));
        assertEquals(response.getState(), params.get("state"));
    }

    @Test
    public void shouldRejectAuthorizationCodeParamsWithoutCode() throws Exception {
        DpopIssuanceSessionService service = serviceWithMocks();
        MockHttpSession httpSession = new MockHttpSession();
        IssuerAuthorizeResponse response = service.createAuthorizationUrl(httpSession, "LocalMockid", authorizeRequest());

        assertThrows(InvalidRequestException.class,
                () -> service.authorizationCodeParams(httpSession, response.getState(), " ", "LocalMockid"));
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

        when(issuersService.getIssuerConfiguration("LocalMockid")).thenReturn(configuration);
        when(issuersService.getIssuerDetails("LocalMockid")).thenReturn(issuer);
        when(dpopProofService.selectAlgorithm(any())).thenReturn("ES256");
        stubCreateSession(dpopProofService);

        assertThrows(InvalidRequestException.class,
                () -> service.createAuthorizationUrl(new MockHttpSession(), "LocalMockid", authorizeRequest()));
    }

    private static DpopIssuanceSessionService serviceWithMocks() throws Exception {
        IssuersService issuersService = mock(IssuersService.class);
        DpopProofService dpopProofService = mock(DpopProofService.class);
        DpopIssuanceSessionService service = new DpopIssuanceSessionService(issuersService, dpopProofService);

        CredentialIssuerConfiguration configuration =
                getCredentialIssuerConfigurationResponseDto("LocalMock", "CredentialType1", List.of());
        IssuerDTO issuer = getIssuerDTO("LocalMock");

        when(issuersService.getIssuerConfiguration("LocalMockid")).thenReturn(configuration);
        when(issuersService.getIssuerDetails("LocalMockid")).thenReturn(issuer);
        when(dpopProofService.selectAlgorithm(any())).thenReturn("ES256");
        stubCreateSession(dpopProofService);
        return service;
    }

    private static void stubCreateSession(DpopProofService dpopProofService) throws Exception {
        when(dpopProofService.createSession(any(), eq("LocalMockid"), eq("ES256"), any(), any()))
                .thenAnswer(invocation -> DpopIssuanceSession.builder()
                        .state(invocation.getArgument(0))
                        .jkt("thumbprint")
                        .build());
    }

    private static IssuerAuthorizeRequest authorizeRequest() {
        IssuerAuthorizeRequest request = new IssuerAuthorizeRequest();
        request.setRedirectUri("https://injiweb.example.com/redirect");
        request.setScope("openid MockVerifiableCredential");
        request.setResponseType("code");
        request.setUiLocales("en");
        return request;
    }
}
