package edu.sde.sharedsecurity.dto;

import jakarta.validation.constraints.NotBlank;

public record AuthRequest(
    @NotBlank(message = "client_id is required") 
    String clientId,
    
    @NotBlank(message = "redirect_uri is required") 
    String redirectUri,
    
    @NotBlank(message = "response_type is required") 
    String responseType,
    
    @NotBlank(message = "scope is required") 
    String scope,
    
    @NotBlank(message = "state is required") 
    String state,
    
    String codeChallenge,
    String codeChallengeMethod
) {
    public AuthRequest {
        if ("code".equals(responseType) && (codeChallenge == null || codeChallenge.isBlank())) {
            throw new IllegalArgumentException("code_challenge is required for PKCE flow");
        }
    }
    
    public boolean isPkceFlow() {
        return codeChallenge != null && !codeChallenge.isBlank();
    }
}