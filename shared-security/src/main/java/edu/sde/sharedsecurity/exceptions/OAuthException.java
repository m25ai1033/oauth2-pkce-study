package edu.sde.sharedsecurity.exceptions;

// shared-security/src/main/java/com/oauth/pkce/shared/security/exception/OAuthException.java
public class OAuthException extends RuntimeException {
    private final String error;
    private final String errorDescription;
    
    public OAuthException(String error, String errorDescription) {
        super(errorDescription);
        this.error = error;
        this.errorDescription = errorDescription;
    }
}