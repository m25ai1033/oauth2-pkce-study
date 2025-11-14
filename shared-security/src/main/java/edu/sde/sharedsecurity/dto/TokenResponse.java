package edu.sde.sharedsecurity.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record TokenResponse(
    @JsonProperty("access_token") String accessToken,
    @JsonProperty("token_type") String tokenType,
    @JsonProperty("expires_in") Long expiresIn,
    @JsonProperty("refresh_token") String refreshToken,
    @JsonProperty("scope") String scope,
    @JsonProperty("id_token") String idToken
) {
    public TokenResponse {
        if (accessToken == null || accessToken.isBlank()) {
            throw new IllegalArgumentException("access_token cannot be null or empty");
        }
        if (tokenType == null || tokenType.isBlank()) {
            tokenType = "Bearer";
        }
        if (expiresIn == null) {
            expiresIn = 3600L; // Default 1 hour
        }
    }
    
    public static TokenResponse of(String accessToken, String refreshToken, String scope) {
        return new TokenResponse(accessToken, "Bearer", 3600L, refreshToken, scope, null);
    }
}