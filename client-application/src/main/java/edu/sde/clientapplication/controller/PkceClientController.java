package edu.sde.clientapplication.controller;

@Controller
public class PkceClientController {
    
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, String> codeVerifiers = new ConcurrentHashMap<>();
    
    @GetMapping("/pkce-authorize")
    public String initiatePkceAuthorization() {
        String state = generateRandomString(24);
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);
        
        // Store code verifier for token exchange
        codeVerifiers.put(state, codeVerifier);
        
        String authorizationUrl = "http://localhost:9000/oauth2/authorize?" +
            "response_type=code&" +
            "client_id=pkce-client&" +
            "redirect_uri=http://localhost:8080/login/oauth2/code/pkce-client&" +
            "scope=openid%20profile%20read%20write&" +
            "state=" + state + "&" +
            "code_challenge=" + codeChallenge + "&" +
            "code_challenge_method=S256";
        
        return "redirect:" + authorizationUrl;
    }
    
    @GetMapping("/pkce-callback")
    public String handlePkceCallback(@RequestParam String code, 
                                   @RequestParam String state,
                                   HttpSession session) {
        try {
            String codeVerifier = codeVerifiers.remove(state);
            if (codeVerifier == null) {
                throw new IllegalStateException("No code verifier found for state: " + state);
            }
            
            // Exchange code for token with PKCE
            String tokenResponse = exchangeCodeForToken(code, codeVerifier);
            
            // Store tokens in session
            session.setAttribute("access_token", extractAccessToken(tokenResponse));
            session.setAttribute("id_token", extractIdToken(tokenResponse));
            
            return "redirect:/pkce-dashboard";
            
        } catch (Exception e) {
            return "redirect:/error?message=" + e.getMessage();
        }
    }
    
    private String exchangeCodeForToken(String code, String codeVerifier) {
        WebClient webClient = WebClient.builder().build();
        
        return webClient.post()
            .uri("http://localhost:9000/oauth2/token")
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                .with("client_id", "pkce-client")
                .with("code", code)
                .with("redirect_uri", "http://localhost:8080/login/oauth2/code/pkce-client")
                .with("code_verifier", codeVerifier))
            .retrieve()
            .bodyToMono(String.class)
            .block();
    }
    
    private String generateCodeVerifier() {
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }
    
    private String generateCodeChallenge(String codeVerifier) {
        try {
            byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(bytes, 0, bytes.length);
            byte[] digest = md.digest();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    private String generateRandomString(int length) {
        byte[] randomBytes = new byte[length];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
    
    private String extractAccessToken(String tokenResponse) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readTree(tokenResponse);
        return jsonNode.get("access_token").asText();
    }
    
    private String extractIdToken(String tokenResponse) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readTree(tokenResponse);
        return jsonNode.get("id_token").asText();
    }
}