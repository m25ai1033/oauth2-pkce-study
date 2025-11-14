package edu.sde.sharedsecurity.configs;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "security.pkce")
public class PkceProperties {
    private int codeVerifierMinLength = 43;
    private int codeVerifierMaxLength = 128;
    private String preferredMethod = "S256";

    // Getters and setters
    public int getCodeVerifierMinLength() { return codeVerifierMinLength; }
    public void setCodeVerifierMinLength(int codeVerifierMinLength) { this.codeVerifierMinLength = codeVerifierMinLength; }
    
    public int getCodeVerifierMaxLength() { return codeVerifierMaxLength; }
    public void setCodeVerifierMaxLength(int codeVerifierMaxLength) { this.codeVerifierMaxLength = codeVerifierMaxLength; }
    
    public String getPreferredMethod() { return preferredMethod; }
    public void setPreferredMethod(String preferredMethod) { this.preferredMethod = preferredMethod; }
}