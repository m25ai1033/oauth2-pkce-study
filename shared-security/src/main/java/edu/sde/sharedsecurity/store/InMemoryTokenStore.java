package edu.sde.sharedsecurity.store;

import edu.sde.sharedsecurity.dto.TokenResponse;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryTokenStore implements TokenStore {
    
    private final Map<String, AuthorizationCodeData> authorizationCodes = new ConcurrentHashMap<>();
    private final Map<String, TokenResponse> accessTokens = new ConcurrentHashMap<>();
    private final Map<String, String> refreshTokens = new ConcurrentHashMap<>();
    
    @Override
    public void storeAuthorizationCode(String code, String clientId, String redirectUri, 
                                     String codeChallenge, String codeChallengeMethod, 
                                     String userId) {
        AuthorizationCodeData data = new AuthorizationCodeData(
            clientId, redirectUri, codeChallenge, codeChallengeMethod, userId
        );
        authorizationCodes.put(code, data);
    }
    
    @Override
    public Optional<AuthorizationCodeData> getAuthorizationCodeData(String code) {
        return Optional.ofNullable(authorizationCodes.get(code));
    }
    
    @Override
    public void removeAuthorizationCode(String code) {
        authorizationCodes.remove(code);
    }
    
    @Override
    public void storeAccessToken(String token, TokenResponse tokenResponse, String clientId, String userId) {
        accessTokens.put(token, tokenResponse);
    }
    
    @Override
    public Optional<TokenResponse> getAccessToken(String token) {
        return Optional.ofNullable(accessTokens.get(token));
    }
    
    @Override
    public void removeAccessToken(String token) {
        accessTokens.remove(token);
    }
    
    @Override
    public void storeRefreshToken(String token, String accessToken, String clientId, String userId) {
        refreshTokens.put(token, accessToken);
    }
    
    @Override
    public Optional<String> getAccessTokenForRefreshToken(String refreshToken) {
        return Optional.ofNullable(refreshTokens.get(refreshToken));
    }
    
    @Override
    public void removeRefreshToken(String refreshToken) {
        refreshTokens.remove(refreshToken);
    }
}