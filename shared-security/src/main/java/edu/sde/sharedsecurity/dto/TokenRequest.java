package edu.sde.sharedsecurity.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record TokenRequest(
    @NotBlank @JsonProperty("grant_type") String grantType,
    @NotBlank String code,
    @NotBlank @JsonProperty("redirect_uri") String redirectUri,
    @NotBlank @JsonProperty("client_id") String clientId,
    @JsonProperty("code_verifier") String codeVerifier,
    @JsonProperty("client_secret") String clientSecret,
    @JsonProperty("refresh_token") String refreshToken
) {
    public boolean isAuthorizationCodeGrant() {
        return "authorization_code".equals(grantType);
    }
    
    public boolean isRefreshTokenGrant() {
        return "refresh_token".equals(grantType);
    }
    
    public boolean requiresPkce() {
        return isAuthorizationCodeGrant() && codeVerifier != null && !codeVerifier.isBlank();
    }
}