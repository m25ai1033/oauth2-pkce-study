package edu.sde.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan("edu.sde.sharedsecurity.configs") // Add this line
public class AuthServerApplication {

    static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }
}
