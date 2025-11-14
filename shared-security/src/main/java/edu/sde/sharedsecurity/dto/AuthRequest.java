package edu.sde.sharedsecurity.dto;

public record AuthRequest(
    @NotBlank String clientId,
    @NotBlank String redirectUri,
    @NotBlank String scope,
    @NotBlank String state,
    String codeChallenge,
    String codeChallengeMethod
) {}