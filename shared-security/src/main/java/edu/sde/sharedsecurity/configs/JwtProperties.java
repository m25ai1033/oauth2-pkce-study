package edu.sde.sharedsecurity.configs;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "security.jwt")
public class JwtProperties {
    private String issuer = "http://localhost:9000/auth";
    private String audience = "http://localhost:8080";
    private long accessTokenValidity = 3600L;
    private long refreshTokenValidity = 2592000L;

    // Getters and setters
    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    
    public String getAudience() { return audience; }
    public void setAudience(String audience) { this.audience = audience; }
    
    public long getAccessTokenValidity() { return accessTokenValidity; }
    public void setAccessTokenValidity(long accessTokenValidity) { this.accessTokenValidity = accessTokenValidity; }
    
    public long getRefreshTokenValidity() { return refreshTokenValidity; }
    public void setRefreshTokenValidity(long refreshTokenValidity) { this.refreshTokenValidity = refreshTokenValidity; }
}