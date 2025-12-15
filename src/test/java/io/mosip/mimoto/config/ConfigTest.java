package io.mosip.mimoto.config;

import io.mosip.mimoto.security.oauth2.CustomOAuth2UserService;
import io.mosip.mimoto.security.oauth2.OAuth2AuthenticationFailureHandler;
import io.mosip.mimoto.security.oauth2.OAuth2AuthenticationSuccessHandler;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.session.SessionRepository;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Collection;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ConfigTest {

    @Mock
    private CustomOAuth2UserService customOAuth2UserService;

    @Mock
    private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    @Mock
    private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Mock
    private SessionRepository<?> sessionRepository;

    @Mock
    private CsrfTokenRepository csrfTokenRepository;

    @Mock
    private CsrfToken csrfToken;

    private Config config;

    @BeforeEach
    void setUp() {
        config = new Config();
        ReflectionTestUtils.setField(config, "baseUrl", "http://localhost:8080");
        ReflectionTestUtils.setField(config, "isCORSEnable", true);
        ReflectionTestUtils.setField(config, "origins", "localhost:8088,localhost:3000");
        ReflectionTestUtils.setField(config, "ignoreAuthUrls", new String[]{"/public/**", "/actuator/**"});
        ReflectionTestUtils.setField(config, "csrfIgnoreUrls", new String[]{"/oauth2/**", "/logout"});
        ReflectionTestUtils.setField(config, "injiWebUrl", "http://localhost:3000");
        ReflectionTestUtils.setField(config, "customOAuth2UserService", customOAuth2UserService);
        ReflectionTestUtils.setField(config, "oAuth2AuthenticationSuccessHandler", oAuth2AuthenticationSuccessHandler);
        ReflectionTestUtils.setField(config, "oAuth2AuthenticationFailureHandler", oAuth2AuthenticationFailureHandler);
    }

    @Test
    void testInjiConfigBean() {
        Map<String, String> injiConfig = config.injiConfig();
        assertNotNull(injiConfig);
        assertInstanceOf(Map.class, injiConfig);
    }

    @Test
    void testCorsConfigurationSource() {
        CorsConfigurationSource corsConfigurationSource = config.corsConfigurationSource();
        assertNotNull(corsConfigurationSource);

        HttpServletRequest request = new MockHttpServletRequest();
        org.springframework.web.cors.CorsConfiguration corsConfig = corsConfigurationSource.getCorsConfiguration(request);
        assertNotNull(corsConfig);
        // Origins are split by comma - check that both origins are present
        assertTrue(corsConfig.getAllowedOrigins().contains("localhost:8088"), "Should contain localhost:8088");
        assertTrue(corsConfig.getAllowedOrigins().contains("localhost:3000"), "Should contain localhost:3000");
        assertEquals(2, corsConfig.getAllowedOrigins().size(), "Should have exactly 2 origins");
        assertTrue(corsConfig.getAllowedMethods().contains("*"));
        assertTrue(corsConfig.getAllowedHeaders().contains("*"));
        assertTrue(corsConfig.getAllowCredentials());
    }

    @Test
    void testCorsConfigurationSourceWithSingleOrigin() {
        ReflectionTestUtils.setField(config, "origins", "localhost:8088");
        CorsConfigurationSource corsConfigurationSource = config.corsConfigurationSource();
        assertNotNull(corsConfigurationSource);

        HttpServletRequest request = new MockHttpServletRequest();
        org.springframework.web.cors.CorsConfiguration corsConfig = corsConfigurationSource.getCorsConfiguration(request);
        assertNotNull(corsConfig);
        assertEquals(1, corsConfig.getAllowedOrigins().size());
        assertTrue(corsConfig.getAllowedOrigins().contains("localhost:8088"));
    }

    @Test
    void testCsrfTokenCookieFilterGetRequestGeneratesToken() throws Exception {
        // Setup
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        when(csrfTokenRepository.loadToken(any())).thenReturn(null);
        when(csrfTokenRepository.generateToken(any())).thenReturn(csrfToken);

        // Create filter instance using reflection
        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify
        verify(csrfTokenRepository).loadToken(any());
        verify(csrfTokenRepository).generateToken(any());
        verify(csrfTokenRepository).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
        assertNotNull(request.getAttribute(CsrfToken.class.getName()));
    }

    @Test
    void testCsrfTokenCookieFilterGetRequestLoadsExistingToken() throws Exception {
        // Setup
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        when(csrfTokenRepository.loadToken(any())).thenReturn(csrfToken);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify
        verify(csrfTokenRepository).loadToken(any());
        verify(csrfTokenRepository, never()).generateToken(any());
        verify(csrfTokenRepository).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterGetRequestPreventsDuplicateCookie() throws Exception {
        // Setup
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.addHeader("Set-Cookie", "XSRF-TOKEN=existing-token; Path=/");
        FilterChain filterChain = mock(FilterChain.class);

        when(csrfTokenRepository.loadToken(any())).thenReturn(csrfToken);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should not save again if cookie already exists
        verify(csrfTokenRepository).loadToken(any());
        verify(csrfTokenRepository, never()).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterPostRequestDoesNotInterfere() throws Exception {
        // Setup
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        // Simulate CsrfFilter already set the token
        request.setAttribute(CsrfToken.class.getName(), csrfToken);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should not process POST requests
        verify(csrfTokenRepository, never()).loadToken(any());
        verify(csrfTokenRepository, never()).generateToken(any());
        verify(csrfTokenRepository, never()).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterPutRequestDoesNotInterfere() throws Exception {
        // Setup
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("PUT");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should not process PUT requests
        verify(csrfTokenRepository, never()).loadToken(any());
        verify(csrfTokenRepository, never()).generateToken(any());
        verify(csrfTokenRepository, never()).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterDeleteRequestDoesNotInterfere() throws Exception {
        // Setup
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("DELETE");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should not process DELETE requests
        verify(csrfTokenRepository, never()).loadToken(any());
        verify(csrfTokenRepository, never()).generateToken(any());
        verify(csrfTokenRepository, never()).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterHeadRequestDoesNotProcess() throws Exception {
        // Setup
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("HEAD");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - HEAD requests should not be processed (only GET is handled)
        verify(csrfTokenRepository, never()).loadToken(any());
        verify(csrfTokenRepository, never()).generateToken(any());
        verify(csrfTokenRepository, never()).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterGetRequestWithTokenAlreadySet() throws Exception {
        // Setup
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.setAttribute(CsrfToken.class.getName(), csrfToken);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should use existing token and save it
        verify(csrfTokenRepository, never()).loadToken(any());
        verify(csrfTokenRepository, never()).generateToken(any());
        verify(csrfTokenRepository).saveToken(eq(csrfToken), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterGetRequestChecksForDuplicateCookie() throws Exception {
        // Setup
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.addHeader("Set-Cookie", "XSRF-TOKEN=test-token-123; Path=/");
        FilterChain filterChain = mock(FilterChain.class);

        when(csrfTokenRepository.loadToken(any())).thenReturn(csrfToken);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should detect duplicate and not save again
        Collection<String> setCookieHeaders = response.getHeaders("Set-Cookie");
        long xsrfTokenCount = setCookieHeaders.stream().filter(header -> header != null && header.startsWith("XSRF-TOKEN=")).count();

        assertEquals(1, xsrfTokenCount, "Should have only one XSRF-TOKEN cookie");
        verify(csrfTokenRepository, never()).saveToken(any(), any(), any());
    }

    @Test
    void testCsrfTokenCookieFilterGetRequestWithNullCookieHeader() throws Exception {
        // Setup - test null cookie header handling
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.addHeader("Set-Cookie", null); // Add null header
        response.addHeader("Set-Cookie", "OTHER-COOKIE=value; Path=/");
        FilterChain filterChain = mock(FilterChain.class);

        when(csrfTokenRepository.loadToken(any())).thenReturn(csrfToken);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should handle null cookie header gracefully and save token
        verify(csrfTokenRepository).loadToken(any());
        verify(csrfTokenRepository).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterGetRequestWithMultipleCookies() throws Exception {
        // Setup - multiple cookies but no XSRF-TOKEN
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.addHeader("Set-Cookie", "SESSION_ID=abc123; Path=/");
        response.addHeader("Set-Cookie", "OTHER_TOKEN=xyz; Path=/");
        FilterChain filterChain = mock(FilterChain.class);

        when(csrfTokenRepository.loadToken(any())).thenReturn(csrfToken);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should save token since XSRF-TOKEN is not present
        verify(csrfTokenRepository).loadToken(any());
        verify(csrfTokenRepository).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterPatchRequestDoesNotInterfere() throws Exception {
        // Setup
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("PATCH");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should not process PATCH requests
        verify(csrfTokenRepository, never()).loadToken(any());
        verify(csrfTokenRepository, never()).generateToken(any());
        verify(csrfTokenRepository, never()).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterOptionsRequestDoesNotInterfere() throws Exception {
        // Setup
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("OPTIONS");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should not process OPTIONS requests
        verify(csrfTokenRepository, never()).loadToken(any());
        verify(csrfTokenRepository, never()).generateToken(any());
        verify(csrfTokenRepository, never()).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterGetRequestLowercaseMethod() throws Exception {
        // Setup - test case-insensitive method check
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("get"); // lowercase
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        when(csrfTokenRepository.loadToken(any())).thenReturn(null);
        when(csrfTokenRepository.generateToken(any())).thenReturn(csrfToken);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should process lowercase GET
        verify(csrfTokenRepository).loadToken(any());
        verify(csrfTokenRepository).generateToken(any());
        verify(csrfTokenRepository).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCorsConfigurationSourceWithEmptyOrigins() {
        ReflectionTestUtils.setField(config, "origins", "");
        CorsConfigurationSource corsConfigurationSource = config.corsConfigurationSource();
        assertNotNull(corsConfigurationSource);

        HttpServletRequest request = new MockHttpServletRequest();
        CorsConfiguration corsConfig = corsConfigurationSource.getCorsConfiguration(request);
        assertNotNull(corsConfig);
        // Empty string split by comma results in array with one empty string
        assertTrue(corsConfig.getAllowedOrigins().contains(""));
    }

    @Test
    void testCorsConfigurationSourceWithWhitespaceInOrigins() {
        ReflectionTestUtils.setField(config, "origins", "localhost:8088 , localhost:3000");
        CorsConfigurationSource corsConfigurationSource = config.corsConfigurationSource();
        assertNotNull(corsConfigurationSource);

        HttpServletRequest request = new MockHttpServletRequest();
        CorsConfiguration corsConfig = corsConfigurationSource.getCorsConfiguration(request);
        assertNotNull(corsConfig);
        // Should contain origins with whitespace (not trimmed)
        assertTrue(corsConfig.getAllowedOrigins().size() >= 2);
    }

    @Test
    void testCsrfTokenCookieFilterGetRequestCookieHeaderWithNullValue() throws Exception {
        // Setup - test null handling in cookie header loop
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();
        // Add a null header value
        response.addHeader("Set-Cookie", null);
        FilterChain filterChain = mock(FilterChain.class);

        when(csrfTokenRepository.loadToken(any())).thenReturn(csrfToken);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should handle null gracefully and save token
        verify(csrfTokenRepository).loadToken(any());
        verify(csrfTokenRepository).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterGetRequestMultipleXSRFTokenCookies() throws Exception {
        // Setup - multiple XSRF-TOKEN cookies (edge case)
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.addHeader("Set-Cookie", "XSRF-TOKEN=token1; Path=/");
        response.addHeader("Set-Cookie", "XSRF-TOKEN=token2; Path=/");
        FilterChain filterChain = mock(FilterChain.class);

        when(csrfTokenRepository.loadToken(any())).thenReturn(csrfToken);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should detect duplicate and not save again
        verify(csrfTokenRepository).loadToken(any());
        verify(csrfTokenRepository, never()).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterGetRequestWithCookieNotStartingWithXSRF() throws Exception {
        // Setup - cookie header that contains XSRF but doesn't start with it
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.addHeader("Set-Cookie", "OTHER=XSRF-TOKEN=value; Path=/"); // Contains but doesn't start with
        FilterChain filterChain = mock(FilterChain.class);

        when(csrfTokenRepository.loadToken(any())).thenReturn(csrfToken);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should save token since XSRF-TOKEN doesn't start the cookie header
        verify(csrfTokenRepository).loadToken(any());
        verify(csrfTokenRepository).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterGetRequestWithEmptyCookieHeaders() throws Exception {
        // Setup - no cookie headers at all
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        when(csrfTokenRepository.loadToken(any())).thenReturn(csrfToken);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should save token since no cookies exist
        verify(csrfTokenRepository).loadToken(any());
        verify(csrfTokenRepository).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCsrfTokenCookieFilterGetRequestTokenSetButCookieNotSet() throws Exception {
        // Setup - token already set in request but cookie not in response
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.setAttribute(CsrfToken.class.getName(), csrfToken);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should save token since cookie is not already set
        verify(csrfTokenRepository, never()).loadToken(any());
        verify(csrfTokenRepository, never()).generateToken(any());
        verify(csrfTokenRepository).saveToken(eq(csrfToken), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testCorsConfigurationSourceWithThreeOrigins() {
        ReflectionTestUtils.setField(config, "origins", "localhost:8088,localhost:3000,localhost:9000");
        CorsConfigurationSource corsConfigurationSource = config.corsConfigurationSource();
        assertNotNull(corsConfigurationSource);

        HttpServletRequest request = new MockHttpServletRequest();
        CorsConfiguration corsConfig = corsConfigurationSource.getCorsConfiguration(request);
        assertNotNull(corsConfig);
        assertEquals(3, corsConfig.getAllowedOrigins().size());
        assertTrue(corsConfig.getAllowedOrigins().contains("localhost:8088"));
        assertTrue(corsConfig.getAllowedOrigins().contains("localhost:3000"));
        assertTrue(corsConfig.getAllowedOrigins().contains("localhost:9000"));
    }

    @Test
    void testCorsConfigurationSourceWithSingleComma() {
        ReflectionTestUtils.setField(config, "origins", ",");
        CorsConfigurationSource corsConfigurationSource = config.corsConfigurationSource();
        assertNotNull(corsConfigurationSource);

        HttpServletRequest request = new MockHttpServletRequest();
        CorsConfiguration corsConfig = corsConfigurationSource.getCorsConfiguration(request);
        assertNotNull(corsConfig);
        assertEquals(0, corsConfig.getAllowedOrigins().size());
    }

    @Test
    void testInjiConfigBeanIsEmptyMap() {
        Map<String, String> injiConfig = config.injiConfig();
        assertNotNull(injiConfig);
        assertTrue(injiConfig.isEmpty()); // Should be empty initially
    }

    @Test
    void testCsrfTokenCookieFilterGetRequestCaseInsensitiveMethod() throws Exception {
        // Setup - test case-insensitive GET method
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GeT"); // Mixed case
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        when(csrfTokenRepository.loadToken(any())).thenReturn(null);
        when(csrfTokenRepository.generateToken(any())).thenReturn(csrfToken);

        Config.CsrfTokenCookieFilter filter = createFilterInstance();

        // Execute
        filter.doFilterInternal(request, response, filterChain);

        // Verify - should process mixed case GET
        verify(csrfTokenRepository).loadToken(any());
        verify(csrfTokenRepository).generateToken(any());
        verify(csrfTokenRepository).saveToken(any(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    /**
     * Helper method to create filter instance
     */
    private Config.CsrfTokenCookieFilter createFilterInstance() {
        return new Config.CsrfTokenCookieFilter(csrfTokenRepository);
    }
}

