package edu.sde.sharedsecurity.utils;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import edu.sde.sharedsecurity.configs.SecurityConstants;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@Component
public class JwtUtil {
    
    public JWTClaimsSet parseToken(String token, RSAPublicKey publicKey) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            
            // Verify signature
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            if (!signedJWT.verify(verifier)) {
                throw new SecurityException("Invalid JWT signature");
            }
            
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            
            // Validate expiration
            if (isTokenExpired(claims.getExpirationTime())) {
                throw new SecurityException("Token has expired");
            }
            
            // Validate issuer
            if (!SecurityConstants.JWT_ISSUER.equals(claims.getIssuer())) {
                throw new SecurityException("Invalid token issuer");
            }
            
            return claims;
            
        } catch (ParseException e) {
            throw new SecurityException("Invalid JWT format", e);
        } catch (Exception e) {
            throw new SecurityException("JWT validation failed", e);
        }
    }
    
    public boolean isTokenExpired(Date expiration) {
        return expiration != null && expiration.before(Date.from(Instant.now()));
    }
    
    public String getSubject(String token, RSAPublicKey publicKey) {
        try {
            JWTClaimsSet claims = parseToken(token, publicKey);
            return claims.getSubject();
        } catch (SecurityException e) {
            return null;
        }
    }
    
    public List<String> getScopes(String token, RSAPublicKey publicKey) {
        try {
            JWTClaimsSet claims = parseToken(token, publicKey);
            return claims.getStringListClaim("scope");
        } catch (ParseException e) {
            throw new SecurityException("Invalid scope claim", e);
        }
    }
    
    public boolean hasScope(String token, RSAPublicKey publicKey, String requiredScope) {
        List<String> scopes = getScopes(token, publicKey);
        return scopes != null && scopes.contains(requiredScope);
    }
}