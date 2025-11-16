package edu.sde.clientapplication.controller;


import edu.sde.sharedsecurity.utils.EnhancedPKCEUtil;
import edu.sde.sharedsecurity.utils.PKCEChallenge;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.UUID;

@Controller
public class ManualAuthController {

    @Value("${client.auth-server-base-url:http://localhost:9000/auth}")
    private String authServerBaseUrl;

    @Value("${client.auth-server-authorize-endpoint:http://localhost:9000/auth/oauth2/authorize}")
    private String authorizeEndpoint;

    @Value("${client.auth-server-token-endpoint:http://localhost:9000/auth/oauth2/token}")
    private String tokenEndpoint;

    @Autowired private EnhancedPKCEUtil enhancedpkceUtil;
    @Autowired private RestTemplate restTemplate;

    @GetMapping("/manual-auth")
    public String manualAuth(HttpSession session, Model model) {
        // Generate PKCE challenge
        PKCEChallenge challenge = enhancedpkceUtil.generateS256Challenge();
        
        // Generate state parameter for CSRF protection
        String state = UUID.randomUUID().toString();
        
        // Store in session for later verification
        session.setAttribute("pkce_code_verifier", challenge.codeVerifier());
        session.setAttribute("oauth_state", state);

        String redirectUri = "http://localhost:8080/manual-callback";
        // Build authorization URL
        String authorizationUrl = UriComponentsBuilder.fromHttpUrl(authorizeEndpoint)
                .queryParam("response_type", "code")
                .queryParam("client_id", "web-app")
                .queryParam("scope", "openid")
                .queryParam("state", state)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("code_challenge", challenge.codeChallenge())
                .queryParam("code_challenge_method", challenge.method())
                .build()
                .toUriString();
        
        model.addAttribute("authorizationUrl", authorizationUrl);
        model.addAttribute("codeVerifier", challenge.codeVerifier());
        model.addAttribute("codeChallenge", challenge.codeChallenge());
        model.addAttribute("state", state);
        
        return "manual-auth";
    }

    @GetMapping("/redirect-auth")
    public String redirectAuth() {
        // Redirect to OAuth2 authorization
        return "redirect:/oauth2/authorization/web-app";
    }

//    @GetMapping("/dashboard")
//    public String dashboard() {
//        return "dashboard";
//    }

    @GetMapping("/manual-callback")
    public String manualCallback(
            @RequestParam("code") String authorizationCode,
            @RequestParam("state") String state,
            @RequestParam(value = "error", required = false) String error,
            HttpSession session,
            Model model) {
        
        // Verify state parameter
        String savedState = (String) session.getAttribute("oauth_state");
        if (!state.equals(savedState)) {
            model.addAttribute("error", "Invalid state parameter");
            return "error";
        }
        
        if (error != null) {
            model.addAttribute("error", "Authorization failed: " + error);
            return "error";
        }
        
        try {
            // Get code verifier from session
            String codeVerifier = (String) session.getAttribute("pkce_code_verifier");
            
            // Exchange authorization code for tokens
            TokenExchangeResponse tokenResponse = exchangeCodeForTokens(authorizationCode, codeVerifier);
            
            // Clear session attributes
            session.removeAttribute("pkce_code_verifier");
            session.removeAttribute("oauth_state");
            
            model.addAttribute("authorizationCode", authorizationCode);
            model.addAttribute("tokenResponse", tokenResponse);
            
            return "manual-callback";
            
        } catch (Exception e) {
            model.addAttribute("error", "Token exchange failed: " + e.getMessage());
            return "error";
        }
    }
    
    private TokenExchangeResponse exchangeCodeForTokens(String authorizationCode, String codeVerifier) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("code", authorizationCode);
        body.add("redirect_uri", "http://localhost:8080/manual-callback");
        body.add("client_id", "web-app");
        body.add("code_verifier", codeVerifier);
        
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        
        try {
            ResponseEntity<TokenExchangeResponse> response = restTemplate.exchange(
                tokenEndpoint,
                HttpMethod.POST,
                request,
                TokenExchangeResponse.class
            );
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                return response.getBody();
            } else {
                throw new RuntimeException("Token request failed: " + response.getStatusCode());
            }
        } catch (Exception e) {
            throw new RuntimeException("Token exchange error: " + e.getMessage(), e);
        }
    }

    // Record for type-safe token response
    public static class TokenExchangeResponse {
        private String access_token;
        private String token_type;
        private Long expires_in;
        private String refresh_token;
        private String scope;
        private String id_token;

        // Default constructor for Jackson
        public TokenExchangeResponse() {}

        // Getters and setters
        public String getAccess_token() { return access_token; }
        public void setAccess_token(String access_token) { this.access_token = access_token; }
        
        public String getToken_type() { return token_type; }
        public void setToken_type(String token_type) { this.token_type = token_type; }
        
        public Long getExpires_in() { return expires_in; }
        public void setExpires_in(Long expires_in) { this.expires_in = expires_in; }
        
        public String getRefresh_token() { return refresh_token; }
        public void setRefresh_token(String refresh_token) { this.refresh_token = refresh_token; }
        
        public String getScope() { return scope; }
        public void setScope(String scope) { this.scope = scope; }
        
        public String getId_token() { return id_token; }
        public void setId_token(String id_token) { this.id_token = id_token; }

        @Override
        public String toString() {
            return "TokenExchangeResponse{" +
                    "access_token='" + (access_token != null ? access_token.substring(0, Math.min(20, access_token.length())) + "..." : "null") + '\'' +
                    ", token_type='" + token_type + '\'' +
                    ", expires_in=" + expires_in +
                    ", refresh_token='" + (refresh_token != null ? "***" : "null") + '\'' +
                    ", scope='" + scope + '\'' +
                    ", id_token='" + (id_token != null ? id_token.substring(0, Math.min(20, id_token.length())) + "..." : "null") + '\'' +
                    '}';
        }
    }
}