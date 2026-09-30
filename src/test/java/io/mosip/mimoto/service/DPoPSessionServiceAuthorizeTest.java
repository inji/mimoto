package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.dpop.DPoPSession;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.exception.InvalidRequestException;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;

import java.util.List;

import static io.mosip.mimoto.util.TestUtilities.getCredentialIssuerConfigurationResponseDto;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DPoPSessionServiceAuthorizeTest {

    @Test
    public void should_createDPoPSession_when_authorizationServerIsProvided() {
        DPoPSessionService service = serviceWithMocks();

        DPoPSession session = service.createSession("oauth-state",
                issuerConfiguration().getAuthorizationServerWellKnownResponse());

        assertEquals("oauth-state", session.getState());
        assertEquals("ES256", session.getAlg());
        assertEquals("https://dev/token", session.getTokenHtu());
    }

    @Test
    public void should_throwInvalidRequest_when_stateIsBlank() {
        DPoPSessionService service = serviceWithMocks();

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> service.createSession(" ", issuerConfiguration().getAuthorizationServerWellKnownResponse()));
        assertEquals("state cannot be blank", exception.getErrorText());
    }

    @Test
    public void should_keepBothDPoPStates_when_concurrentStoresComplete() throws Exception {
        DPoPSessionService service = serviceWithMocks();
        MockHttpSession httpSession = new MockHttpSession();
        DPoPSession first = DPoPSession.builder()
                .state("state-a")
                .build();
        DPoPSession second = DPoPSession.builder()
                .state("state-b")
                .build();

        Thread firstStore = new Thread(() -> service.store(httpSession, first));
        Thread secondStore = new Thread(() -> service.store(httpSession, second));
        firstStore.start();
        secondStore.start();
        firstStore.join();
        secondStore.join();

        assertNotNull(service.find(httpSession, "state-a"));
        assertNotNull(service.find(httpSession, "state-b"));

        service.remove(httpSession, "state-a");
        assertNull(service.find(httpSession, "state-a"));
        assertNotNull(service.find(httpSession, "state-b"));
    }

    @Test
    public void should_generateCredentialProof_when_tokenTypeIsBearer() {
        DPoPManager dPoPManager = mock(DPoPManager.class);
        DPoPSessionService service = new DPoPSessionService(dPoPManager);
        MockHttpSession httpSession = new MockHttpSession();
        DPoPSession session = DPoPSession.builder().state("oauth-state").alg("ES256").jwkJson("{}").build();
        service.store(httpSession, session);
        TokenResponseDTO token = TokenResponseDTO.builder()
                .access_token("access-token")
                .token_type("Bearer")
                .build();
        when(dPoPManager.generateCredentialProof(session, "https://issuer.example.com/credential", "access-token"))
                .thenReturn("dpop-proof");

        String proof = service.credentialProof(httpSession, "oauth-state", token, "https://issuer.example.com/credential");

        assertEquals("dpop-proof", proof);
    }

    private static DPoPSessionService serviceWithMocks() {
        DPoPManager dPoPManager = mock(DPoPManager.class);
        when(dPoPManager.selectAlgorithm(any())).thenReturn("ES256");
        when(dPoPManager.createSession(any(), eq("ES256"), any()))
                .thenAnswer(invocation -> DPoPSession.builder()
                        .state(invocation.getArgument(0))
                        .alg("ES256")
                        .jwkJson("{}")
                        .tokenHtu(invocation.getArgument(2))
                        .build());
        return new DPoPSessionService(dPoPManager);
    }

    private static CredentialIssuerConfiguration issuerConfiguration() {
        return getCredentialIssuerConfigurationResponseDto("LocalMock", "CredentialType1", List.of());
    }
}
