package edu.sde.resourceserver.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class ResourceController {

    // Public endpoint
    @GetMapping("/public/info")
    public Map<String, String> publicInfo() {
        return Map.of(
            "message", "This is public information",
            "timestamp", java.time.Instant.now().toString()
        );
    }

    // Protected user endpoint
    @GetMapping("/protected/user/profile")
    @PreAuthorize("hasAuthority('SCOPE_profile')")
    public Map<String, Object> userProfile(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
            "message", "User profile data",
            "user_id", jwt.getSubject(),
            "username", jwt.getClaimAsString("preferred_username"),
            "email", jwt.getClaimAsString("email"),
            "scopes", jwt.getClaimAsString("scope"),
            "issued_at", jwt.getIssuedAt(),
            "expires_at", jwt.getExpiresAt()
        );
    }

    // Protected admin endpoint
    @GetMapping("/protected/admin/data")
    @PreAuthorize("hasAuthority('SCOPE_write')")
    public Map<String, Object> adminData(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
            "message", "Admin data access",
            "user", jwt.getSubject(),
            "permissions", "Full write access",
            "sensitive_data", "Confidential information"
        );
    }

    // Token introspection endpoint
    @GetMapping("/protected/token-info")
    public Map<String, Object> tokenInfo(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
            "subject", jwt.getSubject(),
            "issuer", jwt.getIssuer(),
            "audience", jwt.getAudience(),
            "issued_at", jwt.getIssuedAt(),
            "expires_at", jwt.getExpiresAt(),
            "scopes", jwt.getClaimAsString("scope"),
            "claims", jwt.getClaims()
        );
    }
}