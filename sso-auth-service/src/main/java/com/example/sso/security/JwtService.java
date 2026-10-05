package com.example.sso.security;

import com.example.sso.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private final JwtProperties props;
    private final SecretKey key;

    public JwtService(JwtProperties props) {
        this.props = props;
        this.key = Keys.hmacShaKeyFor(props.secret().getBytes(StandardCharsets.UTF_8)); // needs >= 32 bytes
    }

    public String generate(String username, Set<String> roles, TokenType type) {
        Instant now = Instant.now();
        Duration ttl = type == TokenType.ACCESS ? props.accessTtl() : props.refreshTtl();
        return Jwts.builder()
                .id(UUID.randomUUID().toString()) // jti - used for revocation
                .issuer(props.issuer())
                .subject(username)
                .claim("roles", List.copyOf(roles))
                .claim("type", type.name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(ttl)))
                .signWith(key)
                .compact();
    }

    /** Verifies signature, issuer and expiry. Throws JwtException on any failure. */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .requireIssuer(props.issuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Set<String> rolesOf(Claims claims) {
        Set<String> out = new HashSet<>();
        Object raw = claims.get("roles");
        if (raw instanceof List<?> list) {
            list.forEach(r -> out.add(String.valueOf(r)));
        }
        return out;
    }

    public boolean isType(Claims claims, TokenType type) {
        return type.name().equals(claims.get("type", String.class));
    }

    public long accessTtlSeconds() {
        return props.accessTtl().toSeconds();
    }
}
