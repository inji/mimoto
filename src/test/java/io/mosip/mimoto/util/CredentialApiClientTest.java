package io.mosip.mimoto.util;

import io.mosip.mimoto.constant.DPoPConstants;
import io.mosip.mimoto.exception.DPoPChallengeException;
import io.mosip.mimoto.exception.InvalidRequestException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialApiClientTest {

    private static final String TEST_URI = "https://issuer.example.com/credential";
    private static final String ACCESS_TOKEN = "access-token";
    private static final String DPOP_PROOF = "dpop-proof-jwt";

    @Mock
    private RestTemplate plainRestTemplate;

    @InjectMocks
    private CredentialApiClient credentialApiClient;

    @Test
    void postCredentialApi_shouldRetryWithBearerWhenIssuerRejectsDPoPScheme() {
        TestResponse success = new TestResponse("credential");
        HttpHeaders rejectHeaders = new HttpHeaders();
        rejectHeaders.set(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");

        HttpClientErrorException unauthorized = HttpClientErrorException.create(
                HttpStatus.UNAUTHORIZED, "Unauthorized",
                rejectHeaders, "{}".getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);

        when(plainRestTemplate.exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class), eq(TestResponse.class)))
                .thenThrow(unauthorized)
                .thenReturn(new ResponseEntity<>(success, HttpStatus.OK));

        TestResponse result = credentialApiClient.postCredentialApi(
                TEST_URI, MediaType.APPLICATION_JSON, "request", TestResponse.class,
                ACCESS_TOKEN, DPoPConstants.DPOP_TOKEN_TYPE, DPOP_PROOF);

        assertNotNull(result);
        assertEquals("credential", result.value);
        verify(plainRestTemplate, times(2)).exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class), eq(TestResponse.class));
    }

    @Test
    void postCredentialApi_shouldRetryWithBearerOnXmlForbiddenWithoutWwwAuthenticate() {
        TestResponse success = new TestResponse("credential");
        String xmlBody = "<Map><timestamp>2026-08-25T06:49:57.554+00:00</timestamp><status>403</status><error>Forbidden</error><path>/credential</path></Map>";

        HttpClientErrorException forbidden = HttpClientErrorException.create(
                HttpStatus.FORBIDDEN, "Forbidden",
                new HttpHeaders(), xmlBody.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);

        when(plainRestTemplate.exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class), eq(TestResponse.class)))
                .thenThrow(forbidden)
                .thenReturn(new ResponseEntity<>(success, HttpStatus.OK));

        TestResponse xmlRetryResult = credentialApiClient.postCredentialApi(
                TEST_URI, MediaType.APPLICATION_JSON, "request", TestResponse.class,
                ACCESS_TOKEN, DPoPConstants.DPOP_TOKEN_TYPE, DPOP_PROOF);

        assertNotNull(xmlRetryResult);
        assertEquals("credential", xmlRetryResult.value);
        verify(plainRestTemplate, times(2)).exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class), eq(TestResponse.class));
    }

    @Test
    void postCredentialApi_shouldRetryWithBearerOnForbiddenWithoutWwwAuthenticate() {
        TestResponse success = new TestResponse("credential");
        HttpClientErrorException forbidden = HttpClientErrorException.create(
                HttpStatus.FORBIDDEN, "Forbidden",
                new HttpHeaders(), "{}".getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);

        when(plainRestTemplate.exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class), eq(TestResponse.class)))
                .thenThrow(forbidden)
                .thenReturn(new ResponseEntity<>(success, HttpStatus.OK));

        TestResponse result = credentialApiClient.postCredentialApi(
                TEST_URI, MediaType.APPLICATION_JSON, "request", TestResponse.class,
                ACCESS_TOKEN, DPoPConstants.DPOP_TOKEN_TYPE, DPOP_PROOF);

        assertNotNull(result);
        assertEquals("credential", result.value);
        verify(plainRestTemplate, times(2)).exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class), eq(TestResponse.class));
    }

    @Test
    void postCredentialApi_shouldNotRetryWithBearerWhenIssuerRequiresDPoPBoundToken() {
        String errorBody = "{\"error\":\"invalid_token\",\"error_description\":\"DPoP-bound access token must be presented with a DPoP proof\"}";
        HttpHeaders rejectHeaders = new HttpHeaders();
        rejectHeaders.set(HttpHeaders.WWW_AUTHENTICATE, "DPoP error=\"invalid_token\"");

        HttpClientErrorException unauthorized = HttpClientErrorException.create(
                HttpStatus.UNAUTHORIZED, "Unauthorized",
                rejectHeaders, errorBody.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);

        when(plainRestTemplate.exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class), eq(TestResponse.class)))
                .thenThrow(unauthorized);

        TestResponse result = credentialApiClient.postCredentialApi(
                TEST_URI, MediaType.APPLICATION_JSON, "request", TestResponse.class,
                ACCESS_TOKEN, DPoPConstants.DPOP_TOKEN_TYPE, DPOP_PROOF);

        verify(plainRestTemplate, times(1)).exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class), eq(TestResponse.class));
        assertTrue(result == null || result.value == null);
    }

    @Test
    void postCredentialApi_shouldNotRetryWithBearerOnInvalidDPoPProof() {
        String errorBody = "{\"error\":\"invalid_dpop_proof\",\"error_description\":\"JWT htu claim mismatch\"}";
        HttpHeaders rejectHeaders = new HttpHeaders();
        rejectHeaders.set(HttpHeaders.WWW_AUTHENTICATE, "DPoP error=\"invalid_dpop_proof\"");

        HttpClientErrorException unauthorized = HttpClientErrorException.create(
                HttpStatus.UNAUTHORIZED, "Unauthorized",
                rejectHeaders, errorBody.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);

        when(plainRestTemplate.exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class), eq(TestResponse.class)))
                .thenThrow(unauthorized);

        TestResponse result = credentialApiClient.postCredentialApi(
                TEST_URI, MediaType.APPLICATION_JSON, "request", TestResponse.class,
                ACCESS_TOKEN, DPoPConstants.DPOP_TOKEN_TYPE, DPOP_PROOF);

        verify(plainRestTemplate, times(1)).exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class), eq(TestResponse.class));
        assertTrue(result == null || result.value == null);
    }

    @Test
    void postCredentialApi_shouldSendDPoPWhenProofPresentEvenIfTokenTypeIsBearer() {
        when(plainRestTemplate.exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class), eq(TestResponse.class)))
                .thenReturn(new ResponseEntity<>(new TestResponse("credential"), HttpStatus.OK));

        credentialApiClient.postCredentialApi(
                TEST_URI, MediaType.APPLICATION_JSON, "request", TestResponse.class,
                ACCESS_TOKEN, DPoPConstants.BEARER_TOKEN_TYPE, DPOP_PROOF);

        ArgumentCaptor<HttpEntity> requestCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(plainRestTemplate).exchange(eq(TEST_URI), eq(HttpMethod.POST), requestCaptor.capture(), eq(TestResponse.class));
        HttpHeaders headers = requestCaptor.getValue().getHeaders();
        assertEquals("DPoP " + ACCESS_TOKEN, headers.getFirst(HttpHeaders.AUTHORIZATION));
        assertEquals(DPOP_PROOF, headers.getFirst(DPoPConstants.DPOP_HEADER));
    }

    @Test
    void postCredentialApi_shouldSendDPoPWhenTokenTypeBlankAndProofPresent() {
        when(plainRestTemplate.exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class), eq(TestResponse.class)))
                .thenReturn(new ResponseEntity<>(new TestResponse("credential"), HttpStatus.OK));

        credentialApiClient.postCredentialApi(
                TEST_URI, MediaType.APPLICATION_JSON, "request", TestResponse.class,
                ACCESS_TOKEN, null, DPOP_PROOF);

        ArgumentCaptor<HttpEntity> requestCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(plainRestTemplate).exchange(eq(TEST_URI), eq(HttpMethod.POST), requestCaptor.capture(), eq(TestResponse.class));
        HttpHeaders headers = requestCaptor.getValue().getHeaders();
        assertEquals("DPoP " + ACCESS_TOKEN, headers.getFirst(HttpHeaders.AUTHORIZATION));
        assertEquals(DPOP_PROOF, headers.getFirst(DPoPConstants.DPOP_HEADER));
    }

    @Test
    void postCredentialApi_shouldThrowWhenIssuerRequiresDPoPNonce() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.WWW_AUTHENTICATE, "DPoP error=\"use_dpop_nonce\"");
        headers.set(DPoPConstants.DPOP_NONCE_HEADER, "issuer-nonce");

        HttpClientErrorException unauthorized = HttpClientErrorException.create(
                HttpStatus.UNAUTHORIZED, "Unauthorized",
                headers, "{\"error\":\"use_dpop_nonce\"}".getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);

        when(plainRestTemplate.exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class), eq(TestResponse.class)))
                .thenThrow(unauthorized);

        DPoPChallengeException exception = assertThrows(DPoPChallengeException.class, () ->
                credentialApiClient.postCredentialApi(
                        TEST_URI, MediaType.APPLICATION_JSON, "request", TestResponse.class,
                        ACCESS_TOKEN, DPoPConstants.DPOP_TOKEN_TYPE, DPOP_PROOF));

        assertEquals("issuer-nonce", exception.getResponseHeaders().getFirst(DPoPConstants.DPOP_NONCE_HEADER));
        verify(plainRestTemplate, times(1)).exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class), eq(TestResponse.class));
    }

    @Test
    void should_rejectCredentialRequest_when_endpointIsNotHttps() {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                credentialApiClient.postCredentialApi(
                        "http://issuer.example.com/credential", MediaType.APPLICATION_JSON, "request",
                        TestResponse.class, ACCESS_TOKEN, DPoPConstants.DPOP_TOKEN_TYPE, DPOP_PROOF));

        assertEquals("Credential endpoint must use HTTPS", exception.getErrorText());
        verifyNoInteractions(plainRestTemplate);
    }

    @Test
    void postCredentialApi_shouldMapXmlVcError_when_issuerReturnsXmlErrorBody() {
        String xmlBody = "<VCError><error>ERROR_FETCHING_IDENTITY_DATA</error>"
                + "<error_description>ERROR_FETCHING_IDENTITY_DATA</error_description></VCError>";
        HttpClientErrorException badRequest = HttpClientErrorException.create(
                HttpStatus.BAD_REQUEST, "Bad Request",
                new HttpHeaders(), xmlBody.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);

        when(plainRestTemplate.exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class),
                eq(io.mosip.mimoto.dto.mimoto.V1VCCredentialResponse.class)))
                .thenThrow(badRequest);

        io.mosip.mimoto.dto.mimoto.V1VCCredentialResponse result = credentialApiClient.postCredentialApi(
                TEST_URI, MediaType.APPLICATION_JSON, "request",
                io.mosip.mimoto.dto.mimoto.V1VCCredentialResponse.class,
                ACCESS_TOKEN, DPoPConstants.BEARER_TOKEN_TYPE, null);

        assertNotNull(result);
        assertEquals("ERROR_FETCHING_IDENTITY_DATA", result.getError());
        assertEquals("ERROR_FETCHING_IDENTITY_DATA", result.getErrorDescription());
        verify(plainRestTemplate, times(1)).exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class),
                eq(io.mosip.mimoto.dto.mimoto.V1VCCredentialResponse.class));
    }

    @Test
    void postCredentialApi_shouldMapJsonOAuthError_when_issuerReturnsErrorObject() {
        String errorBody = "{\"error\":\"invalid_dpop_proof\","
                + "\"error_description\":\"This access token is DPoP-bound and cannot be presented as a Bearer token.\"}";
        HttpClientErrorException unauthorized = HttpClientErrorException.create(
                HttpStatus.UNAUTHORIZED, "Unauthorized",
                new HttpHeaders(), errorBody.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);

        when(plainRestTemplate.exchange(eq(TEST_URI), eq(HttpMethod.POST), any(HttpEntity.class),
                eq(io.mosip.mimoto.dto.mimoto.V1VCCredentialResponse.class)))
                .thenThrow(unauthorized);

        io.mosip.mimoto.dto.mimoto.V1VCCredentialResponse result = credentialApiClient.postCredentialApi(
                TEST_URI, MediaType.APPLICATION_JSON, "request",
                io.mosip.mimoto.dto.mimoto.V1VCCredentialResponse.class,
                ACCESS_TOKEN, DPoPConstants.BEARER_TOKEN_TYPE, null);

        assertNotNull(result);
        assertEquals("invalid_dpop_proof", result.getError());
        assertEquals("This access token is DPoP-bound and cannot be presented as a Bearer token.",
                result.getErrorDescription());
    }

    static class TestResponse {
        public String value;

        public TestResponse() {
        }

        public TestResponse(String value) {
            this.value = value;
        }
    }
}
