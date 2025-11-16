package edu.sde.sharedsecurity.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@EnableConfigurationProperties({JwtProperties.class, PkceProperties.class})
public class SecurityConstants {
    
    // Static constants - can be used anywhere
    
    // JWT Constants
    public static final String JWT_ISSUER = "http://localhost:9000/auth";
    public static final String JWT_AUDIENCE = "http://localhost:8080";
    public static final long ACCESS_TOKEN_VALIDITY_SECONDS = 3600L; // 1 hour
    public static final long REFRESH_TOKEN_VALIDITY_SECONDS = 2592000L; // 30 days
    
    // PKCE Constants
    public static final String CODE_CHALLENGE_METHOD_S256 = "S256";
    public static final String CODE_CHALLENGE_METHOD_PLAIN = "plain";
    public static final int CODE_VERIFIER_MIN_LENGTH = 43;
    public static final int CODE_VERIFIER_MAX_LENGTH = 128;
    
    // OAuth2 Constants
    public static final String AUTHORIZATION_CODE_GRANT = "authorization_code";
    public static final String REFRESH_TOKEN_GRANT = "refresh_token";
    public static final String CLIENT_CREDENTIALS_GRANT = "client_credentials";
    public static final String DEFAULT_SCOPE = "read write";
    
    // Security Constants
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String BASIC_PREFIX = "Basic ";
    public static final String ROLE_USER = "ROLE_USER";
    public static final String ROLE_CLIENT = "ROLE_CLIENT";
    public static final String ROLE_ADMIN = "ROLE_ADMIN";
    
    // JWT Claim Names
    public static final String JWT_CLAIM_SCOPE = "scope";
    public static final String JWT_CLAIM_ROLES = "roles";
    public static final String JWT_CLAIM_CLIENT_ID = "client_id";
    public static final String JWT_CLAIM_USER_NAME = "user_name";
    
    // Instance properties for configuration
    private final JwtProperties jwtProperties;
    private final PkceProperties pkceProperties;

    @Autowired
    public SecurityConstants(JwtProperties jwtProperties, PkceProperties pkceProperties) {
        this.jwtProperties = jwtProperties;
        this.pkceProperties = pkceProperties;
    }
    
    // Instance methods for configuration-based values with fallbacks to static constants
    public String getJwtIssuer() { 
        return jwtProperties != null && jwtProperties.getIssuer() != null ? 
               jwtProperties.getIssuer() : JWT_ISSUER; 
    }
    
    public String getJwtAudience() { 
        return jwtProperties != null && jwtProperties.getAudience() != null ? 
               jwtProperties.getAudience() : JWT_AUDIENCE; 
    }
    
    public long getAccessTokenValidity() { 
        return jwtProperties != null ? jwtProperties.getAccessTokenValidity() : ACCESS_TOKEN_VALIDITY_SECONDS; 
    }
    
    public long getRefreshTokenValidity() { 
        return jwtProperties != null ? jwtProperties.getRefreshTokenValidity() : REFRESH_TOKEN_VALIDITY_SECONDS; 
    }
    
    public int getCodeVerifierMinLength() { 
        return pkceProperties != null ? pkceProperties.getCodeVerifierMinLength() : CODE_VERIFIER_MIN_LENGTH; 
    }
    
    public int getCodeVerifierMaxLength() { 
        return pkceProperties != null ? pkceProperties.getCodeVerifierMaxLength() : CODE_VERIFIER_MAX_LENGTH; 
    }
    
    public String getPreferredCodeChallengeMethod() { 
        return pkceProperties != null && pkceProperties.getPreferredMethod() != null ? 
               pkceProperties.getPreferredMethod() : CODE_CHALLENGE_METHOD_S256; 
    }
    
    // Static utility methods
    public static boolean isValidCodeChallengeMethod(String method) {
        return CODE_CHALLENGE_METHOD_S256.equals(method) || 
               CODE_CHALLENGE_METHOD_PLAIN.equals(method);
    }
    
    public static boolean isValidCodeVerifierLength(String codeVerifier) {
        if (codeVerifier == null) return false;
        int length = codeVerifier.length();
        return length >= CODE_VERIFIER_MIN_LENGTH && length <= CODE_VERIFIER_MAX_LENGTH;
    }
    
    public static boolean isValidCodeVerifier(String codeVerifier) {
        if (codeVerifier == null || codeVerifier.isBlank()) {
            return false;
        }
        
        int length = codeVerifier.length();
        if (length < CODE_VERIFIER_MIN_LENGTH || length > CODE_VERIFIER_MAX_LENGTH) {
            return false;
        }
        
        // Check if all characters are valid according to RFC 7636
        String validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        return codeVerifier.chars().allMatch(ch -> validChars.indexOf(ch) >= 0);
    }
    
    public static boolean isBearerToken(String authorizationHeader) {
        return authorizationHeader != null && authorizationHeader.startsWith(BEARER_PREFIX);
    }
    
    public static String extractBearerToken(String authorizationHeader) {
        if (isBearerToken(authorizationHeader)) {
            return authorizationHeader.substring(BEARER_PREFIX.length());
        }
        return null;
    }
}