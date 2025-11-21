package io.mosip.mimoto.config;


import io.mosip.injivcrenderer.InjiVcRenderer;
import io.mosip.pixelpass.PixelPass;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {
    @Bean
    public CredentialsVerifier credentialsVerifier() {
        return new CredentialsVerifier();
    }

    @Bean
    public PixelPass pixelPass() {
        return new PixelPass();
    }

    @Bean
    public InjiVcRenderer injiVcRenderer() {
        return new InjiVcRenderer("inji-web");
    }
}
