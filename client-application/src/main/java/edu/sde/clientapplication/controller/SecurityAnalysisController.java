package edu.sde.clientapplication.controller;

@Controller
public class SecurityAnalysisController {
    
    @GetMapping("/security-analysis")
    public String securityAnalysis(Model model) {
        
        // PKCE Security Benefits
        List<SecurityFeature> pkceBenefits = Arrays.asList(
            new SecurityFeature("Mitigates Authorization Code Interception", 
                "Prevents attackers from using stolen authorization codes", "HIGH"),
            new SecurityFeature("Protects Public Clients", 
                "Especially valuable for mobile apps and SPAs", "HIGH"),
            new SecurityFeature("No Impact on User Experience", 
                "Transparent to end users", "MEDIUM"),
            new SecurityFeature("Backwards Compatible", 
                "Can be gradually adopted", "LOW")
        );
        
        // Attack Scenarios
        List<AttackScenario> attackScenarios = Arrays.asList(
            new AttackScenario("Traditional OAuth2 without PKCE", 
                "Authorization code interception attack possible", "VULNERABLE"),
            new AttackScenario("PKCE-Enhanced OAuth2", 
                "Code interception prevented by code verifier requirement", "PROTECTED"),
            new AttackScenario("Malicious Redirect URI", 
                "Still prevented by redirect URI validation", "PROTECTED")
        );
        
        model.addAttribute("pkceBenefits", pkceBenefits);
        model.addAttribute("attackScenarios", attackScenarios);
        
        return "security-analysis";
    }
    
    // Data classes
    public static class SecurityFeature {
        private String title;
        private String description;
        private String impact;
        
        // constructor, getters, setters
    }
    
    public static class AttackScenario {
        private String scenario;
        private String outcome;
        private String status;
        
        // constructor, getters, setters
    }
}