package io.mosip.mimoto.config;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.URIScheme;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;


@Configuration
@ComponentScan(basePackages = {
        "io.mosip.mimoto.*" }, excludeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, value = {
        Config.class, OpenApiProperties.class, SwaggerConfig.class}))
public class MimotoConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.headers(headersEntry -> {
            headersEntry.cacheControl(Customizer.withDefaults());
            headersEntry.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin);
        });

        return http.build();
    }

    @Bean
    public RestTemplate selfTokenRestTemplate()
            throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {

        final RestTemplate restTemplate = new RestTemplate();

        SSLContext sslContext = SSLContextBuilder.create()
                .loadTrustMaterial((X509Certificate[] certificateChain, String authType) -> true)  // <--- accepts each certificate
                .build();

        Registry<ConnectionSocketFactory> socketRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register(URIScheme.HTTPS.getId(), new SSLConnectionSocketFactory(sslContext))
                .register(URIScheme.HTTP.getId(), new PlainConnectionSocketFactory())
                .build();

        HttpClient httpClient = HttpClientBuilder.create()
                .setConnectionManager(new PoolingHttpClientConnectionManager(socketRegistry))
                .setConnectionManagerShared(true)
                .build();

        ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        restTemplate.setRequestFactory(requestFactory);
        return restTemplate;

    }

    @Bean
    public RestTemplate plainRestTemplate()
            throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
        return selfTokenRestTemplate();
    }

}
