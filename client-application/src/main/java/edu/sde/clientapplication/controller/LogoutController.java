package edu.sde.clientapplication.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class LogoutController {

    @Value("${client.auth-server-base-url:http://localhost:9000/auth}")
    private String authServerBaseUrl;

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response, Model model) {
        // Clear the authentication
        SecurityContextHolder.clearContext();
        
        // Invalidate the session
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        
        // Clear cookies
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                cookie.setMaxAge(0);
                cookie.setValue(null);
                cookie.setPath("/");
                response.addCookie(cookie);
            }
        }
        
        // Build OIDC logout URL (if your auth server supports it)
        String oidcLogoutUrl = authServerBaseUrl + "/connect/logout";
        model.addAttribute("oidcLogoutUrl", oidcLogoutUrl);
        
        return "logout";
    }

    @PostMapping("/logout")
    public String performLogout(HttpServletRequest request, HttpServletResponse response) {
        // Perform the same cleanup as GET logout
        SecurityContextHolder.clearContext();
        
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        
        return "redirect:/?logout";
    }

    // Optional: Global logout (logs out from auth server too)
    @GetMapping("/global-logout")
    public String globalLogout(HttpServletRequest request, HttpServletResponse response) {
        // Clear local session first
        SecurityContextHolder.clearContext();
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        
        // Redirect to auth server's logout endpoint
        String logoutUrl = authServerBaseUrl + "/connect/logout";
        return "redirect:" + logoutUrl;
    }
}