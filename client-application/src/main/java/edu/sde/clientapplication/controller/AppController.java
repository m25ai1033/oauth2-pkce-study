package edu.sde.clientapplication.controller;

import edu.sde.sharedsecurity.utils.EnhancedPKCEUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;

import java.util.LinkedHashMap;
import java.util.Map;

@Controller
public class AppController {

    @Value("${client.auth-server-base-url:http://localhost:9000/auth}")
    private String authServerBaseUrl;

    @Value("${client.auth-server-authorize-endpoint:http://localhost:9000/auth/oauth2/authorize}")
    private String authorizeEndpoint;

    @Value("${client.auth-server-token-endpoint:http://localhost:9000/auth/oauth2/token}")
    private String tokenEndpoint;

    @Autowired
    private EnhancedPKCEUtil enhancedpkceUtil;
    @Autowired private RestTemplate restTemplate;

    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("message", "Welcome to OAuth 2.0 PKCE Client Demo");
        return "index";
    }

    @GetMapping("/public")
    public String publicPage(Model model) {
        model.addAttribute("message", "This is a public page - no authentication required");
        return "public";
    }

    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal OAuth2User user, Model model) {
        if (user != null) {
            model.addAttribute("user", user);
            model.addAttribute("claims", user.getAttributes());
        }
        return "dashboard";
    }

    @GetMapping("/profile")
    public String profile(@AuthenticationPrincipal OidcUser user, Model model) {
        if (user != null) {
            model.addAttribute("user", user);

            try {
                Map<String, Object> profile = new LinkedHashMap<>();
                profile.put("name", user.getFullName());
                profile.put("email", user.getEmail());
                profile.put("subject", user.getSubject());
                profile.put("givenName", user.getGivenName());
                profile.put("familyName", user.getFamilyName());
                profile.put("emailVerified", user.getEmailVerified());

                // Add all attributes for debugging
                model.addAttribute("allAttributes", user.getAttributes());

                model.addAttribute("profile", profile);

            } catch (Exception e) {
                model.addAttribute("error", "Error loading profile: " + e.getMessage());
            }
        } else {
            model.addAttribute("error", "User not authenticated");
        }
        return "profile";
    }
}