package edu.sde.maliciousclient.dto;

import java.time.LocalDateTime;

// Record to store intercepted code information
    public record InterceptedCode(
        String id,
        String authorizationCode,
        LocalDateTime interceptedAt,
        boolean attackAttempted,
        boolean attackSuccessful,
        LocalDateTime lastAttackAttempt
    ) {
        public InterceptedCode(String id, String authorizationCode, LocalDateTime interceptedAt) {
            this(id, authorizationCode, interceptedAt, false, false, null);
        }
        
        public InterceptedCode markAttackAttempted() {
            return new InterceptedCode(id, authorizationCode, interceptedAt, true, attackSuccessful, LocalDateTime.now());
        }
        
        public InterceptedCode markAttackSuccessful() {
            return new InterceptedCode(id, authorizationCode, interceptedAt, true, true, LocalDateTime.now());
        }
    }