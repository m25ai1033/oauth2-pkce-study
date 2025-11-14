package edu.sde.sharedsecurity.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class PKCEUtilTest {
    
    private final PKCEUtil pkceUtil = new PKCEUtil();
    
    @Test
    void generateS256Challenge_shouldReturnValidChallenge() {
        PKCEChallenge challenge = pkceUtil.generateS256Challenge();
        
        assertNotNull(challenge.codeVerifier());
        assertNotNull(challenge.codeChallenge());
        assertEquals("S256", challenge.method());
        assertTrue(challenge.codeVerifier().length() >= 43);
        assertTrue(challenge.codeVerifier().length() <= 128);
    }
    
    @Test
    void verifyCodeChallenge_withValidS256_shouldReturnTrue() {
        PKCEChallenge challenge = pkceUtil.generateS256Challenge();
        
        boolean isValid = pkceUtil.verifyCodeChallenge(
            challenge.codeVerifier(), 
            challenge.codeChallenge(), 
            challenge.method()
        );
        
        assertTrue(isValid);
    }
    
    @Test
    void verifyCodeChallenge_withInvalidVerifier_shouldReturnFalse() {
        PKCEChallenge challenge = pkceUtil.generateS256Challenge();
        
        boolean isValid = pkceUtil.verifyCodeChallenge(
            "invalid_verifier", 
            challenge.codeChallenge(), 
            challenge.method()
        );
        
        assertFalse(isValid);
    }
}