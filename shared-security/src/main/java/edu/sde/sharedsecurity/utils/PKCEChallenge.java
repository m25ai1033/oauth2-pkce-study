package edu.sde.sharedsecurity.utils;


import edu.sde.sharedsecurity.configs.SecurityConstants;

public record PKCEChallenge(
    String codeVerifier,
    String codeChallenge,
    String method
) {
    public PKCEChallenge {
        if (codeVerifier == null || codeVerifier.isBlank()) {
            throw new IllegalArgumentException("codeVerifier cannot be null or empty");
        }
        if (codeChallenge == null || codeChallenge.isBlank()) {
            throw new IllegalArgumentException("codeChallenge cannot be null or empty");
        }
        if (method == null || method.isBlank()) {
            method = SecurityConstants.CODE_CHALLENGE_METHOD_S256;
        }
        
        // Validate code verifier length according to RFC 7636
        if (codeVerifier.length() < SecurityConstants.CODE_VERIFIER_MIN_LENGTH || 
            codeVerifier.length() > SecurityConstants.CODE_VERIFIER_MAX_LENGTH) {
            throw new IllegalArgumentException("Code verifier must be between 43 and 128 characters");
        }
    }
    
    public boolean isValidMethod() {
        return SecurityConstants.CODE_CHALLENGE_METHOD_S256.equals(method) || 
               SecurityConstants.CODE_CHALLENGE_METHOD_PLAIN.equals(method);
    }
}