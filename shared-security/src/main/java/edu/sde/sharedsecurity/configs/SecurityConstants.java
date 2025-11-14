package edu.sde.sharedsecurity.configs;

// shared-security/src/main/java/com/oauth/pkce/shared/security/config/SecurityConstants.java
public class SecurityConstants {
    public static final String JWT_ISSUER = "http://auth-server:9000";
    public static final String JWT_AUDIENCE = "http://resource-server:8080";
    public static final long ACCESS_TOKEN_VALIDITY = 3600L; // 1 hour
    public static final long REFRESH_TOKEN_VALIDITY = 2592000L; // 30 days
}