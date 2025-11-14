package edu.sde.shared_security.dto;

public record TokenResponse(
    String access_token,
    String token_type,
    Long expires_in,
    String refresh_token,
    String scope
) {}
