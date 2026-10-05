package com.example.sso.auth;

public record TokenResponse(String accessToken, String refreshToken, String tokenType, long expiresInSeconds) { }
