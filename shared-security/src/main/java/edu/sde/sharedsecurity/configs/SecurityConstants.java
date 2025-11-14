package edu.sde.sharedsecurity.configs;

public class SecurityConstants {
    
    // JWT Configuration
    public static final String JWT_ISSUER = "http://localhost:9000";
    public static final String JWT_AUDIENCE = "http://localhost:8081";
    public static final long ACCESS_TOKEN_VALIDITY_SECONDS = 3600L; // 1 hour
    public static final long REFRESH_TOKEN_VALIDITY_SECONDS = 2592000L; // 30 days
    
    // PKCE Configuration
    public static final int CODE_VERIFIER_MIN_LENGTH = 43;
    public static final int CODE_VERIFIER_MAX_LENGTH = 128;
    public static final String CODE_CHALLENGE_METHOD_S256 = "S256";
    public static final String CODE_CHALLENGE_METHOD_PLAIN = "plain";
    
    // OAuth2 Configuration
    public static final String AUTHORIZATION_CODE_GRANT = "authorization_code";
    public static final String REFRESH_TOKEN_GRANT = "refresh_token";
    public static final String DEFAULT_SCOPE = "read write";
    
    // HTTP Headers
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    
    // Security Context
    public static final String ROLE_USER = "ROLE_USER";
    public static final String ROLE_CLIENT = "ROLE_CLIENT";
    
    private SecurityConstants() {
        // Utility class
    }
}