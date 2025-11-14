package edu.sde.sharedsecurity.store;

import com.oauth.pkce.shared.security.dto.TokenResponse;

import java.util.Optional;

public interface TokenStore {
    
    void storeAuthorizationCode(String code, String clientId, String redirectUri, 
                               String codeChallenge, String codeChallengeMethod, 
                               String userId);
    
    Optional<AuthorizationCodeData> getAuthorizationCodeData(String code);
    
    void removeAuthorizationCode(String code);
    
    void storeAccessToken(String token, TokenResponse tokenResponse, String clientId, String userId);
    
    Optional<TokenResponse> getAccessToken(String token);
    
    void removeAccessToken(String token);
    
    void storeRefreshToken(String token, String accessToken, String clientId, String userId);
    
    Optional<String> getAccessTokenForRefreshToken(String refreshToken);
    
    void removeRefreshToken(String refreshToken);
    
    record AuthorizationCodeData(
        String clientId,
        String redirectUri,
        String codeChallenge,
        String codeChallengeMethod,
        String userId
    ) {}
}