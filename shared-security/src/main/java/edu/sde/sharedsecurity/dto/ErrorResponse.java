package edu.sde.sharedsecurity.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorResponse(
    String error,
    String errorDescription,
    String path,
    Instant timestamp,
    String traceId
) {
    public ErrorResponse(String error, String errorDescription) {
        this(error, errorDescription, null, Instant.now(), null);
    }
    
    public ErrorResponse(String error, String errorDescription, String path) {
        this(error, errorDescription, path, Instant.now(), null);
    }
    
    public static ErrorResponse invalidRequest(String description) {
        return new ErrorResponse("invalid_request", description);
    }
    
    public static ErrorResponse accessDenied(String description) {
        return new ErrorResponse("access_denied", description);
    }
    
    public static ErrorResponse serverError(String description) {
        return new ErrorResponse("server_error", description);
    }
}