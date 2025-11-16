package edu.sde.sharedsecurity.utils;

import edu.sde.sharedsecurity.configs.SecurityConstants;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class EnhancedPKCEUtil {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String CODE_VERIFIER_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    
    public PKCEChallenge generateS256Challenge() {
        String codeVerifier = generateSecureCodeVerifier();
        String codeChallenge = generateS256CodeChallenge(codeVerifier);
        return new PKCEChallenge(codeVerifier, codeChallenge, SecurityConstants.CODE_CHALLENGE_METHOD_S256);
    }
    
    public String generateSecureCodeVerifier() {
        // Generate cryptographically secure random bytes
        byte[] randomBytes = new byte[64]; // 512 bits for extra security
        SECURE_RANDOM.nextBytes(randomBytes);
        
        // Convert to URL-safe base64
        String base64 = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        
        // Ensure it meets length requirements
        if (base64.length() < SecurityConstants.CODE_VERIFIER_MIN_LENGTH) {
            // If too short, append more random characters
            base64 += generateRandomString(SecurityConstants.CODE_VERIFIER_MIN_LENGTH - base64.length());
        } else if (base64.length() > SecurityConstants.CODE_VERIFIER_MAX_LENGTH) {
            // If too long, truncate (very unlikely with 64 bytes)
            base64 = base64.substring(0, SecurityConstants.CODE_VERIFIER_MAX_LENGTH);
        }
        
        return base64;
    }
    
    private String generateRandomString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int index = SECURE_RANDOM.nextInt(CODE_VERIFIER_CHARS.length());
            sb.append(CODE_VERIFIER_CHARS.charAt(index));
        }
        return sb.toString();
    }
    
    public String generateS256CodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
    
    public boolean verifyCodeChallenge(String codeVerifier, String codeChallenge, String method) {
        if (codeVerifier == null || codeChallenge == null || method == null) {
            return false;
        }
        
        if (!isValidCodeVerifier(codeVerifier)) {
            return false;
        }
        
        switch (method) {
            case SecurityConstants.CODE_CHALLENGE_METHOD_S256:
                String computedChallenge = generateS256CodeChallenge(codeVerifier);
                return computedChallenge.equals(codeChallenge);
                
            case SecurityConstants.CODE_CHALLENGE_METHOD_PLAIN:
                return codeVerifier.equals(codeChallenge);
                
            default:
                return false;
        }
    }
    
    public boolean isValidCodeVerifier(String codeVerifier) {
        if (codeVerifier == null || codeVerifier.isBlank()) {
            return false;
        }
        
        int length = codeVerifier.length();
        if (length < SecurityConstants.CODE_VERIFIER_MIN_LENGTH || 
            length > SecurityConstants.CODE_VERIFIER_MAX_LENGTH) {
            return false;
        }
        
        // Check if all characters are valid according to RFC 7636
        return codeVerifier.chars()
            .allMatch(ch -> CODE_VERIFIER_CHARS.indexOf(ch) >= 0);
    }
    
    public boolean isValidCodeChallengeMethod(String method) {
        return SecurityConstants.CODE_CHALLENGE_METHOD_S256.equals(method) || 
               SecurityConstants.CODE_CHALLENGE_METHOD_PLAIN.equals(method);
    }
    
    /**
     * Validates if the PKCE flow parameters are properly formed
     */
    public boolean validatePkceParameters(String codeVerifier, String codeChallenge, String method) {
        if (codeVerifier == null || codeChallenge == null || method == null) {
            return false;
        }
        
        if (!isValidCodeVerifier(codeVerifier)) {
            return false;
        }
        
        if (!isValidCodeChallengeMethod(method)) {
            return false;
        }
        
        return verifyCodeChallenge(codeVerifier, codeChallenge, method);
    }
    
    /**
     * Generates a PKCE challenge with specified method
     */
    public PKCEChallenge generateChallenge(String method) {
        if (!isValidCodeChallengeMethod(method)) {
            throw new IllegalArgumentException("Invalid code challenge method: " + method);
        }
        
        String codeVerifier = generateSecureCodeVerifier();
        String codeChallenge;
        
        if (SecurityConstants.CODE_CHALLENGE_METHOD_S256.equals(method)) {
            codeChallenge = generateS256CodeChallenge(codeVerifier);
        } else {
            codeChallenge = codeVerifier; // For plain method
        }
        
        return new PKCEChallenge(codeVerifier, codeChallenge, method);
    }
}