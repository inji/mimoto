package io.mosip.mimoto.config;

import io.mosip.mimoto.security.oauth2.CustomOAuth2UserService;
import io.mosip.mimoto.security.oauth2.OAuth2AuthenticationFailureHandler;
import io.mosip.mimoto.security.oauth2.OAuth2AuthenticationSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.session.SessionRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static io.mosip.mimoto.exception.ErrorConstants.LOGIN_SESSION_INVALIDATE_EXCEPTION;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Order(1)
@Slf4j
public class Config {

    // CSRF Configuration Constants
    private static final String CSRF_COOKIE_PATH = "/";
    private static final String CSRF_COOKIE_NAME = "XSRF-TOKEN";
    private static final String CSRF_HEADER_NAME = "X-XSRF-TOKEN";
    private static final String CSRF_COOKIE_HEADER_PREFIX = "XSRF-TOKEN=";

    // HTTP Method Constants
    private static final String HTTP_METHOD_GET = "GET";

    @Value("${mosipbox.public.url}")
    private String baseUrl;

    @Value("${mosip.security.cors-enable:false}")
    private boolean isCORSEnable;

    @Value("${mosip.security.origins:localhost:8088}")
    private String origins;

    @Value("${mosip.security.ignore-auth-urls}")
    private String[] ignoreAuthUrls;

    @Value("${mosip.security.csrf-ignore-urls}")
    private String[] csrfIgnoreUrls;

    @Value("${mosip.inji.web.url}")
    private String injiWebUrl;

    @Bean
    @ConfigurationProperties(prefix = "mosip.inji")
    public Map<String, String> injiConfig() {
        return new HashMap<>();
    }

    @Autowired
    private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    @Autowired
    private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;

    private CookieCsrfTokenRepository csrfTokenRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, SessionRepository sessionRepository) throws Exception {
        configureCsrf(http);
        http.addFilterAfter(new CsrfTokenCookieFilter(csrfTokenRepository), org.springframework.security.web.csrf.CsrfFilter.class);

        if (isCORSEnable) {
            http.cors(corsCustomizer -> corsCustomizer
                    .configurationSource(corsConfigurationSource()));
        }
        http.headers(headersEntry -> {
            headersEntry.cacheControl(Customizer.withDefaults());
            headersEntry.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin);
        });

        setupOauth2Config(http, sessionRepository);

        http.exceptionHandling(exceptionHandling ->
                exceptionHandling.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
        );


        return http.build();

    }

    private void configureCsrf(HttpSecurity http) throws Exception {
        csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfTokenRepository.setCookiePath(CSRF_COOKIE_PATH);
        csrfTokenRepository.setCookieName(CSRF_COOKIE_NAME);
        csrfTokenRepository.setHeaderName(CSRF_HEADER_NAME);

        CsrfTokenRequestHandler requestHandler = new CsrfTokenRequestAttributeHandler();

        if (csrfIgnoreUrls != null && csrfIgnoreUrls.length > 0) {
            http.csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository).csrfTokenRequestHandler(requestHandler).ignoringRequestMatchers(csrfIgnoreUrls));
        } else {
            http.csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository).csrfTokenRequestHandler(requestHandler));
        }
    }

    private void setupOauth2Config(HttpSecurity http, SessionRepository sessionRepository) throws Exception {
        configureOAuth2Login(http);
        configureLogout(http, sessionRepository);
        configureAuthorization(http);
        configureSessionManagement(http);
    }

    private void configureOAuth2Login(HttpSecurity http) throws Exception {
        http.oauth2Login(oauth2Login -> oauth2Login
                .loginPage(injiWebUrl + "/")
                .authorizationEndpoint(authorization -> authorization.baseUri("/oauth2/authorize"))
                .redirectionEndpoint(redirect -> redirect.baseUri("/oauth2/callback/*"))
                .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler)
        );
    }

    private void configureLogout(HttpSecurity http, SessionRepository<?> sessionRepository) throws Exception {
        http.logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessHandler((request, response, authentication) -> {
                    // If authentication is not null, it was a valid logout.
                    if (authentication != null) {
                        response.setStatus(HttpStatus.OK.value());
                        response.setContentType("application/json");
                        response.getWriter().write("{\"status\":\"success\", \"message\":\"Logout successful\"}");
                    } else {
                        response.setStatus(HttpStatus.NOT_FOUND.value());
                        response.setContentType("application/json");
                        String jsonResponse = String.format("{\"errors\":[{\"errorCode\":\"%s\",\"errorMessage\":\"%s\"}]}",
                                LOGIN_SESSION_INVALIDATE_EXCEPTION.getErrorCode(),
                                LOGIN_SESSION_INVALIDATE_EXCEPTION.getErrorMessage());
                        response.getWriter().write(jsonResponse);
                    }
                })
        );
    }


    private void configureAuthorization(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authz -> authz
                .requestMatchers(ignoreAuthUrls).permitAll()
                .anyRequest().authenticated()
        );
    }

    private void configureSessionManagement(HttpSecurity http) throws Exception {
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
    }

    // Define CORS configuration
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(Arrays.asList(origins.split(",")));  // Allow all origins
        corsConfiguration.addAllowedHeader("*");  // Allow all headers
        corsConfiguration.addAllowedMethod("*");  // Allow all HTTP methods
        corsConfiguration.setAllowCredentials(true);// Allow cookies to be sent
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }

    /**
     * Filter to ensure CSRF tokens are generated and stored in cookies on all requests,
     * including GET requests. This ensures the XSRF-TOKEN cookie is available for clients
     * to read and use in subsequent state-changing requests.
     */
    static class CsrfTokenCookieFilter extends OncePerRequestFilter {

        private final CsrfTokenRepository csrfTokenRepository;

        public CsrfTokenCookieFilter(CsrfTokenRepository csrfTokenRepository) {
            this.csrfTokenRepository = csrfTokenRepository;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
            CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

            boolean isGetRequest = HTTP_METHOD_GET.equalsIgnoreCase(request.getMethod());
            if (isGetRequest) {
                if (csrfToken == null) {
                    csrfToken = csrfTokenRepository.loadToken(request);
                    if (csrfToken == null) {
                        csrfToken = csrfTokenRepository.generateToken(request);
                    }
                    request.setAttribute(CsrfToken.class.getName(), csrfToken);
                }

                boolean cookieAlreadySet = false;
                Collection<String> setCookieHeaders = response.getHeaders("Set-Cookie");
                for (String cookieHeader : setCookieHeaders) {
                    if (cookieHeader != null && cookieHeader.startsWith(CSRF_COOKIE_HEADER_PREFIX)) {
                        cookieAlreadySet = true;
                        break;
                    }
                }

                if (!cookieAlreadySet) {
                    csrfTokenRepository.saveToken(csrfToken, request, response);
                }
            }

            filterChain.doFilter(request, response);
        }
    }

}
