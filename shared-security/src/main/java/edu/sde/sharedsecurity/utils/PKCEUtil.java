package edu.sde.sharedsecurity.utils;

import edu.sde.sharedsecurity.configs.SecurityConstants;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class PKCEUtil {
    
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String CODE_VERIFIER_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    
    public PKCEChallenge generateS256Challenge() {
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateS256CodeChallenge(codeVerifier);
        return new PKCEChallenge(codeVerifier, codeChallenge, "S256");
    }
    
    public String generateCodeVerifier() {
        return RandomStringUtils.random(
            SecurityConstants.CODE_VERIFIER_MAX_LENGTH,
            0,
            CODE_VERIFIER_CHARS.length(),
            false,
            false,
            CODE_VERIFIER_CHARS.toCharArray(),
            SECURE_RANDOM
        );
    }
    
    public String generateS256CodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes());
            return base64UrlEncode(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
    
    public boolean verifyCodeChallenge(String codeVerifier, String codeChallenge, String method) {
        if (codeVerifier == null || codeChallenge == null || method == null) {
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
    
    private String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
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
}