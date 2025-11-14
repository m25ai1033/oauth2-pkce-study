package edu.sde.sharedsecurity.configs;

public record ClientConfig(
    String clientId,
    String clientSecret,
    String clientName,
    String[] redirectUris,
    String[] scope,
    boolean requirePkce,
    boolean confidentialClient
) {
    
    public boolean isValidRedirectUri(String redirectUri) {
        for (String validUri : redirectUris) {
            if (validUri.equals(redirectUri)) {
                return true;
            }
        }
        return false;
    }
    
    public boolean isValidScope(String requestedScope) {
        if (requestedScope == null || requestedScope.isBlank()) {
            return true; // Use default scope
        }
        
        String[] requestedScopes = requestedScope.split(" ");
        for (String scope : requestedScopes) {
            boolean found = false;
            for (String validScope : this.scope) {
                if (validScope.equals(scope)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }
}