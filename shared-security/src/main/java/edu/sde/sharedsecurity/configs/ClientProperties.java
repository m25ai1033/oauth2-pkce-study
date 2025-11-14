package edu.sde.sharedsecurity.configs;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@ConfigurationProperties(prefix = "security.clients")
public class ClientProperties {
    private Map<String, ClientConfig> webClient = new HashMap<>();
    private Map<String, ClientConfig> mobileClient = new HashMap<>();
    private Map<String, ClientConfig> testClient = new HashMap<>();

    // Getters and setters
    public Map<String, ClientConfig> getWebClient() { return webClient; }
    public void setWebClient(Map<String, ClientConfig> webClient) { this.webClient = webClient; }
    
    public Map<String, ClientConfig> getMobileClient() { return mobileClient; }
    public void setMobileClient(Map<String, ClientConfig> mobileClient) { this.mobileClient = mobileClient; }
    
    public Map<String, ClientConfig> getTestClient() { return testClient; }
    public void setTestClient(Map<String, ClientConfig> testClient) { this.testClient = testClient; }

    public static class ClientConfig {
        private String clientId;
        private String clientSecret;
        private String redirectUris;
        private String scope;
        private boolean requirePkce;
        private boolean confidential;

        // Getters and setters
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        
        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
        
        public String getRedirectUris() { return redirectUris; }
        public void setRedirectUris(String redirectUris) { this.redirectUris = redirectUris; }
        
        public String getScope() { return scope; }
        public void setScope(String scope) { this.scope = scope; }
        
        public boolean isRequirePkce() { return requirePkce; }
        public void setRequirePkce(boolean requirePkce) { this.requirePkce = requirePkce; }
        
        public boolean isConfidential() { return confidential; }
        public void setConfidential(boolean confidential) { this.confidential = confidential; }
    }
}