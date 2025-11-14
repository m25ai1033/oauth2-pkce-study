package edu.sde.clientapplication.controller;

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

import java.util.Map;
import java.util.UUID;

@Controller
public class ManualAuthController {

    @Value("${client.auth-server-base-url:http://localhost:9000}")
    private String authServerBaseUrl;

    @Value("${client.auth-server-authorize-endpoint:http://localhost:9000/oauth2/authorize}")
    private String authorizeEndpoint;

    @Value("${client.auth-server-token-endpoint:http://localhost:9000/oauth2/token}")
    private String tokenEndpoint;

    private final EnhancedPKCEUtil pkceUtil;
    private final RestTemplate restTemplate;

    @Autowired
    public ManualAuthController(EnhancedPKCEUtil pkceUtil) {
        this.pkceUtil = pkceUtil;
        this.restTemplate = new RestTemplate();
    }

    @GetMapping("/manual-auth")
    public String manualAuth(HttpSession session, Model model) {
        // Generate PKCE challenge
        PKCEChallenge challenge = pkceUtil.generateS256Challenge();
        
        // Generate state parameter for CSRF protection
        String state = UUID.randomUUID().toString();
        
        // Store in session for later verification
        session.setAttribute("pkce_code_verifier", challenge.codeVerifier());
        session.setAttribute("oauth_state", state);
        
        // Build authorization URL
        String authorizationUrl = UriComponentsBuilder.fromHttpUrl(authorizeEndpoint)
                .queryParam("response_type", "code")
                .queryParam("client_id", "web-app")
                .queryParam("scope", "openid read write profile")
                .queryParam("state", state)
                .queryParam("redirect_uri", "http://localhost:8080/manual-callback")
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
            Map<String, Object> tokenResponse = exchangeCodeForTokens(authorizationCode, codeVerifier);
            
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
    
    private Map<String, Object> exchangeCodeForTokens(String authorizationCode, String codeVerifier) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("code", authorizationCode);
        body.add("redirect_uri", "http://localhost:8080/manual-callback");
        body.add("client_id", "web-app");
        body.add("code_verifier", codeVerifier);
        
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        
        ResponseEntity<Map> response = restTemplate.exchange(
            tokenEndpoint,
            HttpMethod.POST,
            request,
            Map.class
        );
        
        if (response.getStatusCode() == HttpStatus.OK) {
            return response.getBody();
        } else {
            throw new RuntimeException("Token request failed: " + response.getStatusCode());
        }
    }
}