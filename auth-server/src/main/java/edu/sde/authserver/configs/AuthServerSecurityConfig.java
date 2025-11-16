package edu.sde.authserver.configs;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.Nullable;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class AuthServerSecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final @Nullable DataSource dataSource;
    private final @Nullable CorsConfigurationSource corsConfigurationSource;
    private final Path jwkFilePath;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public AuthServerSecurityConfig(
            PasswordEncoder passwordEncoder,                                  // now constructor-injected
            @Autowired(required = false) @Nullable DataSource dataSource,
            @Autowired(required = false) @Nullable CorsConfigurationSource corsConfigurationSource,
            @Value("${auth.jwk.location:./keystore.jwks}") String jwkLocation
    ) {
        this.passwordEncoder = passwordEncoder;
        this.dataSource = dataSource;
        this.corsConfigurationSource = corsConfigurationSource;
        this.jwkFilePath = Path.of(jwkLocation);
    }

    // ===============================
    // Authorization Server Security
    // ===============================
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        // Modern API: http.with()
        http.with(authorizationServerConfigurer, config -> {
            config.oidc(Customizer.withDefaults());
            config.authorizationEndpoint(e -> e.consentPage("/oauth2/consent"));
        });

        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher());

        if (corsConfigurationSource != null) {
            http.cors(cors -> cors.configurationSource(corsConfigurationSource));
        }

        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        http.csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher()));
        http.exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
        http.oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()));
        http.formLogin(Customizer.withDefaults());

        http.headers(h -> h.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

        return http.build();
    }

    // ===============================
    // Application Security
    // ===============================
    @Bean
    @Order(2)
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {

        if (corsConfigurationSource != null) {
            http.cors(c -> c.configurationSource(corsConfigurationSource));
        }

        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/error", "/webjars/**", "/h2-console/**", "/actuator/**").permitAll()
                .anyRequest().authenticated()
        );

        http.formLogin(f -> f.loginPage("/login").permitAll());
        http.csrf(c -> c.ignoringRequestMatchers("/h2-console/**"));
        http.headers(h -> h.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

        return http.build();
    }

    // ===============================
    // Users (test)
    // ===============================
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails u1 = User.builder()
                .username("user1")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                .build();

        UserDetails u2 = User.builder()
                .username("user2")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(u1, u2);
    }

    // ===============================
    // Registered Clients
    // ===============================
    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        RegisteredClient webClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("web-app")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:8080/manual-callback")
                .redirectUri("http://localhost:8080/authorized")
                // Make sure these scopes match what you're requesting
                .scope(OidcScopes.OPENID)
                .scope("profile")
                .scope("read")
                .scope("write")
                .scope("email")  // Add if needed
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)  // Set to false for testing
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(false)
                        .build())
                .build();

        System.out.println("Registered client with scopes: " + webClient.getScopes());

        RegisteredClient mobileClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("mobile-app")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("com.oauth.demo:/oauth2redirect")
                .scope(OidcScopes.OPENID)
                .scope("offline_access")
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .build();

        RegisteredClient testClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("test-app")
                .clientSecret(passwordEncoder.encode("test-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8082/auth/callback")
                .scope("read")
                .clientSettings(ClientSettings.builder().requireProofKey(false).build())
                .build();

        if (dataSource != null) {
            var jdbc = new JdbcRegisteredClientRepository(new org.springframework.jdbc.core.JdbcTemplate(dataSource));
            if (jdbc.findByClientId(webClient.getClientId()) == null) jdbc.save(webClient);
            if (jdbc.findByClientId(mobileClient.getClientId()) == null) jdbc.save(mobileClient);
            if (jdbc.findByClientId(testClient.getClientId()) == null) jdbc.save(testClient);
            return jdbc;
        }

        return new InMemoryRegisteredClientRepository(webClient, mobileClient, testClient);
    }

    // ===============================
    // Authorization + Consent Services
    // ===============================
    @Bean
    public OAuth2AuthorizationService authorizationService() {
        if (dataSource != null) {
            return new JdbcOAuth2AuthorizationService(
                    new org.springframework.jdbc.core.JdbcTemplate(dataSource),
                    registeredClientRepository());
        }
        return new org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService authorizationConsentService() {
        if (dataSource != null) {
            return new JdbcOAuth2AuthorizationConsentService(
                    new org.springframework.jdbc.core.JdbcTemplate(dataSource),
                    registeredClientRepository());
        }
        return new org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService();
    }

    // ===============================
    // JWK Source (file-backed)
    // ===============================
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        try {
            RSAKey rsaKey;
            System.out.println("JWK file path: " + jwkFilePath.toAbsolutePath());
            System.out.println("JWK file exists: " + Files.exists(jwkFilePath));

            if (Files.exists(jwkFilePath)) {
                var json = Files.readString(jwkFilePath, StandardCharsets.UTF_8);
                System.out.println("Loading existing JWK from file");
                var jwkSet = JWKSet.parse(json);
                rsaKey = (RSAKey) jwkSet.getKeys().get(0);

                // Check if the loaded key has a private key
                if (!rsaKey.isPrivate()) {
                    System.out.println("WARNING: Loaded JWK has no private key! Generating new one...");
                    rsaKey = generateRsa();
                    saveJwkToFile(rsaKey);
                }
            } else {
                System.out.println("Generating new RSA key and saving to file");
                rsaKey = generateRsa();
                saveJwkToFile(rsaKey);
            }

            // Verify the key is private
            if (!rsaKey.isPrivate()) {
                throw new IllegalStateException("Generated RSA key is not private!");
            }

            System.out.println("RSA key is private: " + rsaKey.isPrivate());
            System.out.println("RSA key ID: " + rsaKey.getKeyID());

            JWKSet jwkSet = new JWKSet(rsaKey);
            return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);

        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private void saveJwkToFile(RSAKey rsaKey) throws IOException {
        var jwkSet = new JWKSet(rsaKey);
        Files.createDirectories(jwkFilePath.getParent());
        String jwkJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jwkSet.toJSONObject());
        Files.writeString(jwkFilePath, jwkJson, StandardCharsets.UTF_8);
        System.out.println("JWK saved to: " + jwkFilePath.toAbsolutePath());
    }

    private static RSAKey generateRsa() {
        KeyPair kp = generateRsaKey();
        return new RSAKey.Builder((RSAPublicKey) kp.getPublic())
                .privateKey((RSAPrivateKey) kp.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() {
        try {
            var gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    // ===============================
    // Jwt Decoder
    // ===============================
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // ===============================
    // Authorization Server Settings
    // ===============================
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(
            @Value("${auth.issuer:http://localhost:9000/auth}") String issuer
    ) {
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .build();
    }
}
