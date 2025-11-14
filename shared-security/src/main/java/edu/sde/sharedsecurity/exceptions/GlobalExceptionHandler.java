package edu.sde.sharedsecurity.exceptions;

import com.oauth.pkce.shared.security.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
    
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    
    @ExceptionHandler(OAuthException.class)
    public ResponseEntity<ErrorResponse> handleOAuthException(OAuthException ex, HttpServletRequest request) {
        log.warn("OAuth exception: {} - {}", ex.getError(), ex.getErrorDescription());
        
        ErrorResponse errorResponse = new ErrorResponse(
            ex.getError(),
            ex.getErrorDescription(),
            request.getRequestURI()
        );
        
        return ResponseEntity.status(ex.getHttpStatus()).body(errorResponse);
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(Exception ex, HttpServletRequest request) {
        log.error("Unexpected error occurred", ex);
        
        ErrorResponse errorResponse = new ErrorResponse(
            "server_error",
            "An internal server error occurred",
            request.getRequestURI()
        );
        
        return ResponseEntity.status(500).body(errorResponse);
    }
}