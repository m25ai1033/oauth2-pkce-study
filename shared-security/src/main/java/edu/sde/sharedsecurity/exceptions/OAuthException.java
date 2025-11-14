package edu.sde.sharedsecurity.exceptions;

import org.springframework.http.HttpStatus;

public class OAuthException extends RuntimeException {
    private final String error;
    private final String errorDescription;
    private final HttpStatus httpStatus;
    
    public OAuthException(String error, String errorDescription, HttpStatus httpStatus) {
        super(errorDescription);
        this.error = error;
        this.errorDescription = errorDescription;
        this.httpStatus = httpStatus;
    }
    
    public OAuthException(String error, String errorDescription) {
        this(error, errorDescription, HttpStatus.BAD_REQUEST);
    }
    
    // Getters
    public String getError() { return error; }
    public String getErrorDescription() { return errorDescription; }
    public HttpStatus getHttpStatus() { return httpStatus; }
    
    // Common OAuth2 exceptions
    public static OAuthException invalidRequest(String description) {
        return new OAuthException("invalid_request", description, HttpStatus.BAD_REQUEST);
    }
    
    public static OAuthException invalidClient(String description) {
        return new OAuthException("invalid_client", description, HttpStatus.UNAUTHORIZED);
    }
    
    public static OAuthException invalidGrant(String description) {
        return new OAuthException("invalid_grant", description, HttpStatus.BAD_REQUEST);
    }
    
    public static OAuthException unauthorizedClient(String description) {
        return new OAuthException("unauthorized_client", description, HttpStatus.BAD_REQUEST);
    }
    
    public static OAuthException unsupportedGrantType(String description) {
        return new OAuthException("unsupported_grant_type", description, HttpStatus.BAD_REQUEST);
    }
    
    public static OAuthException invalidScope(String description) {
        return new OAuthException("invalid_scope", description, HttpStatus.BAD_REQUEST);
    }
    
    public static OAuthException accessDenied(String description) {
        return new OAuthException("access_denied", description, HttpStatus.FORBIDDEN);
    }
}