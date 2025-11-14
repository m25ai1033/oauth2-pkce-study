package edu.sde.sharedsecurity.utils;

// shared-security/src/main/java/com/oauth/pkce/shared/security/util/PKCEUtil.java
@Component
public class PKCEUtil {
    
    public record PKCEChallenge(
        String codeVerifier,
        String codeChallenge,
        String method
    ) {}
    
    public PKCEChallenge generateS256Challenge() {
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateS256CodeChallenge(codeVerifier);
        return new PKCEChallenge(codeVerifier, codeChallenge, "S256");
    }
    
    private String generateCodeVerifier() {
        // Implementation using SecureRandom
    }
    
    private String generateS256CodeChallenge(String codeVerifier) {
        // SHA-256 implementation
    }
    
    public boolean verifyCodeChallenge(String codeVerifier, String codeChallenge, String method) {
        // Verification logic
    }
}