package io.mosip.mimoto.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.*;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RestApiClientTest {

    private static final String TEST_URI = "https://example.com/api";
    private static final String ACCESS_TOKEN = "test-access-token";

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private RestTemplate plainRestTemplate;

    @InjectMocks
    private RestApiClient restApiClient;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(restApiClient, "disableSelfTokenRestTemplate", false);
    }

    // --- getApi(URI, Class) ---

    @Test
    void getApiByUri_shouldReturnResponseBody() throws Exception {
        URI uri = URI.create(TEST_URI);
        ResponseEntity<String> responseEntity = new ResponseEntity<>("response-body", HttpStatus.OK);

        when(restTemplate.exchange(eq(uri), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(responseEntity);

        String result = restApiClient.getApi(uri, String.class);

        assertEquals("response-body", result);
    }

    @Test
    void getApiByUri_shouldUsePlainRestTemplateWhenSelfTokenDisabled() throws Exception {
        ReflectionTestUtils.setField(restApiClient, "disableSelfTokenRestTemplate", true);
        URI uri = URI.create(TEST_URI);
        ResponseEntity<String> responseEntity = new ResponseEntity<>("plain-response", HttpStatus.OK);

        when(plainRestTemplate.exchange(eq(uri), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(responseEntity);

        String result = restApiClient.getApi(uri, String.class);

        assertEquals("plain-response", result);
        verify(restTemplate, never()).exchange(any(URI.class), any(), any(), any(Class.class));
    }

    @Test
    void getApiByUri_shouldReturnNullOnException() throws Exception {
        URI uri = URI.create(TEST_URI);

        when(restTemplate.exchange(eq(uri), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new ResourceAccessException("Connection refused"));

        String result = restApiClient.getApi(uri, String.class);

        assertNull(result);
    }

    // --- getApi(String, Class) ---

    @Test
    void getApiByUrl_shouldReturnResponse() {
        when(restTemplate.getForObject(eq(TEST_URI), eq(String.class)))
                .thenReturn("url-response");

        String result = restApiClient.getApi(TEST_URI, String.class);

        assertEquals("url-response", result);
    }

    @Test
    void getApiByUrl_shouldUsePlainRestTemplateWhenSelfTokenDisabled() {
        ReflectionTestUtils.setField(restApiClient, "disableSelfTokenRestTemplate", true);

        when(plainRestTemplate.getForObject(eq(TEST_URI), eq(String.class)))
                .thenReturn("plain-url-response");

        String result = restApiClient.getApi(TEST_URI, String.class);

        assertEquals("plain-url-response", result);
        verify(restTemplate, never()).getForObject(anyString(), any());
    }

    @Test
    void getApiByUrl_shouldReturnNullOnException() {
        when(restTemplate.getForObject(eq(TEST_URI), eq(String.class)))
                .thenThrow(new ResourceAccessException("Timeout"));

        String result = restApiClient.getApi(TEST_URI, String.class);

        assertNull(result);
    }

    // --- postApi(String, MediaType, Object, Class) ---

    @Test
    void postApi_shouldReturnResponse() throws Exception {
        when(restTemplate.postForObject(eq(TEST_URI), any(HttpEntity.class), eq(String.class)))
                .thenReturn("post-response");

        String result = restApiClient.postApi(TEST_URI, MediaType.APPLICATION_JSON, "request-body", String.class);

        assertEquals("post-response", result);
    }

    @Test
    void postApi_shouldUsePlainRestTemplateWhenSelfTokenDisabled() throws Exception {
        ReflectionTestUtils.setField(restApiClient, "disableSelfTokenRestTemplate", true);

        when(plainRestTemplate.postForObject(eq(TEST_URI), any(HttpEntity.class), eq(String.class)))
                .thenReturn("plain-post-response");

        String result = restApiClient.postApi(TEST_URI, MediaType.APPLICATION_JSON, "request-body", String.class);

        assertEquals("plain-post-response", result);
        verify(restTemplate, never()).postForObject(anyString(), any(), any());
    }

    @Test
    void postApi_shouldReturnNullOnException() throws Exception {
        when(restTemplate.postForObject(eq(TEST_URI), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new ResourceAccessException("Connection refused"));

        String result = restApiClient.postApi(TEST_URI, MediaType.APPLICATION_JSON, "request-body", String.class);

        assertNull(result);
    }

    // --- postApi(String, MediaType, Object, Class, String bearerToken) ---

    @Test
    void postApiWithBearerToken_shouldReturnResponse() {
        when(plainRestTemplate.postForObject(eq(TEST_URI), any(HttpEntity.class), eq(String.class)))
                .thenReturn("bearer-response");

        String result = restApiClient.postApi(TEST_URI, MediaType.APPLICATION_JSON, "request", String.class, ACCESS_TOKEN);

        assertEquals("bearer-response", result);
    }

    @Test
    void postApiWithBearerToken_shouldReturnNullOnException() {
        when(plainRestTemplate.postForObject(eq(TEST_URI), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new ResourceAccessException("Timeout"));

        String result = restApiClient.postApi(TEST_URI, MediaType.APPLICATION_JSON, "request", String.class, ACCESS_TOKEN);

        assertNull(result);
    }

    // --- postApiWithErrorResponse ---

    @Test
    void postApiWithErrorResponse_shouldReturnResponseOnSuccess() {
        TestResponse expected = new TestResponse("ok", null);

        when(plainRestTemplate.postForObject(eq(TEST_URI), any(HttpEntity.class), eq(TestResponse.class)))
                .thenReturn(expected);

        TestResponse result = restApiClient.postApiWithErrorResponse(
                TEST_URI, MediaType.APPLICATION_JSON, "request", TestResponse.class, ACCESS_TOKEN);

        assertNotNull(result);
        assertEquals("ok", result.status);
    }

    @Test
    void postApiWithErrorResponse_shouldParseErrorBodyOnHttpClientError() {
        String errorJson = "{\"status\":null,\"error\":\"invalid_nonce\"}";
        HttpClientErrorException exception = HttpClientErrorException.create(
                HttpStatus.BAD_REQUEST, "Bad Request",
                HttpHeaders.EMPTY, errorJson.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);

        when(plainRestTemplate.postForObject(eq(TEST_URI), any(HttpEntity.class), eq(TestResponse.class)))
                .thenThrow(exception);

        TestResponse result = restApiClient.postApiWithErrorResponse(
                TEST_URI, MediaType.APPLICATION_JSON, "request", TestResponse.class, ACCESS_TOKEN);

        assertNotNull(result);
        assertEquals("invalid_nonce", result.error);
    }

    @Test
    void postApiWithErrorResponse_shouldReturnNullWhenErrorBodyCannotBeParsed() {
        String malformedBody = "not-valid-json";
        HttpClientErrorException exception = HttpClientErrorException.create(
                HttpStatus.BAD_REQUEST, "Bad Request",
                HttpHeaders.EMPTY, malformedBody.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);

        when(plainRestTemplate.postForObject(eq(TEST_URI), any(HttpEntity.class), eq(TestResponse.class)))
                .thenThrow(exception);

        TestResponse result = restApiClient.postApiWithErrorResponse(
                TEST_URI, MediaType.APPLICATION_JSON, "request", TestResponse.class, ACCESS_TOKEN);

        assertNull(result);
    }

    @Test
    void postApiWithErrorResponse_shouldReturnNullOnNonClientError() {
        when(plainRestTemplate.postForObject(eq(TEST_URI), any(HttpEntity.class), eq(TestResponse.class)))
                .thenThrow(new ResourceAccessException("Connection refused"));

        TestResponse result = restApiClient.postApiWithErrorResponse(
                TEST_URI, MediaType.APPLICATION_JSON, "request", TestResponse.class, ACCESS_TOKEN);

        assertNull(result);
    }

    @Test
    void postApiWithErrorResponse_shouldHandleHttpServerError() {
        HttpClientErrorException exception = HttpClientErrorException.create(
                HttpStatus.FORBIDDEN, "Forbidden",
                HttpHeaders.EMPTY, "{}".getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);

        when(plainRestTemplate.postForObject(eq(TEST_URI), any(HttpEntity.class), eq(TestResponse.class)))
                .thenThrow(exception);

        TestResponse result = restApiClient.postApiWithErrorResponse(
                TEST_URI, MediaType.APPLICATION_JSON, "request", TestResponse.class, ACCESS_TOKEN);

        assertNotNull(result);
    }

    // --- getApiWithCustomHeaders ---

    @Test
    void getApiWithCustomHeaders_shouldReturnResponse() {
        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.set("X-Custom", "value");

        ResponseEntity<String> responseEntity = new ResponseEntity<>("custom-response", HttpStatus.OK);

        when(restTemplate.exchange(eq(TEST_URI), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(responseEntity);

        String result = restApiClient.getApiWithCustomHeaders(TEST_URI, String.class, customHeaders);

        assertEquals("custom-response", result);
    }

    @Test
    void getApiWithCustomHeaders_shouldUsePlainRestTemplateWhenSelfTokenDisabled() {
        ReflectionTestUtils.setField(restApiClient, "disableSelfTokenRestTemplate", true);

        HttpHeaders customHeaders = new HttpHeaders();
        ResponseEntity<String> responseEntity = new ResponseEntity<>("plain-custom", HttpStatus.OK);

        when(plainRestTemplate.exchange(eq(TEST_URI), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(responseEntity);

        String result = restApiClient.getApiWithCustomHeaders(TEST_URI, String.class, customHeaders);

        assertEquals("plain-custom", result);
    }

    @Test
    void getApiWithCustomHeaders_shouldReturnNullOnException() {
        HttpHeaders customHeaders = new HttpHeaders();

        when(restTemplate.exchange(eq(TEST_URI), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new ResourceAccessException("Timeout"));

        String result = restApiClient.getApiWithCustomHeaders(TEST_URI, String.class, customHeaders);

        assertNull(result);
    }

    static class TestResponse {
        public String status;
        public String error;

        public TestResponse() {}

        public TestResponse(String status, String error) {
            this.status = status;
            this.error = error;
        }
    }
}
