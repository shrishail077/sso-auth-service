package com.example.sso.security;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * In-memory deny-list of revoked token ids (jti). Entries expire with the token itself.
 * For multi-instance deployments replace with Redis (SETEX jti with the token's remaining TTL).
 */
@Component
public class TokenRevocationStore {

    private final Map<String, Instant> revoked = new ConcurrentHashMap<>();

    public void revoke(String jti, Instant tokenExpiry) {
        revoked.put(jti, tokenExpiry);
    }

    public boolean isRevoked(String jti) {
        Instant now = Instant.now();
        revoked.values().removeIf(exp -> exp.isBefore(now));
        return revoked.containsKey(jti);
    }
}
