package edu.sde.authserver.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class CommonSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // DelegatingPasswordEncoder with bcrypt as default - recommended
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
