package edu.sde.clientapplication.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;

@Controller
public class AppController {

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
    public String dashboard(@AuthenticationPrincipal OidcUser user, Model model) {
        if (user != null) {
            model.addAttribute("user", user);
            model.addAttribute("idToken", user.getIdToken().getTokenValue());
            model.addAttribute("accessToken", user.getAccessTokenHash()); // Note: This is the hash, not the actual token
            model.addAttribute("claims", user.getClaims());
        }
        return "dashboard";
    }

    @GetMapping("/profile")
    public String profile(@AuthenticationPrincipal OidcUser user, Model model) {
        if (user != null) {
            model.addAttribute("user", user);
            model.addAttribute("profile", Map.of(
                "name", user.getFullName(),
                "email", user.getEmail(),
                "subject", user.getSubject()
            ));
        }
        return "profile";
    }
}