package com.example.sso.auth;

import com.example.sso.audit.AuditService;
import com.example.sso.domain.Role;
import com.example.sso.domain.User;
import com.example.sso.repo.UserRepository;
import com.example.sso.security.JwtService;
import com.example.sso.security.TokenRevocationStore;
import com.example.sso.security.TokenType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    private final TokenRevocationStore revocations;
    private final AuditService audit;
    private final String dummyHash;

    public AuthService(UserRepository users, PasswordEncoder encoder, JwtService jwt,
                       TokenRevocationStore revocations, AuditService audit) {
        this.users = users;
        this.encoder = encoder;
        this.jwt = jwt;
        this.revocations = revocations;
        this.audit = audit;
        this.dummyHash = encoder.encode("dummy-password"); // used to equalize timing for unknown users
    }

    public TokenResponse login(LoginRequest req) {
        Optional<Set<String>> roles = authenticate(req.username(), req.password());
        if (roles.isEmpty()) {
            audit.record("LOGIN_FAILURE", req.username(), "bad credentials");
            throw new BadCredentialsException("Invalid credentials"); // same message for every failure cause
        }
        audit.record("LOGIN_SUCCESS", req.username(), "password login");
        return issue(req.username(), roles.get());
    }

    public TokenResponse refresh(String refreshToken) {
        Claims claims = parseOrReject(refreshToken);
        if (!jwt.isType(claims, TokenType.REFRESH) || revocations.isRevoked(claims.getId())) {
            throw new BadCredentialsException("Invalid refresh token");
        }
        // rotation: a refresh token is single-use
        revocations.revoke(claims.getId(), claims.getExpiration().toInstant());
        audit.record("TOKEN_REFRESH", claims.getSubject(), "rotated");
        return issue(claims.getSubject(), jwt.rolesOf(claims));
    }

    public void logout(String accessToken, String refreshToken) {
        String username = revokeQuietly(accessToken);
        if (refreshToken != null && !refreshToken.isBlank()) {
            revokeQuietly(refreshToken);
        }
        audit.record("LOGOUT", username, "tokens revoked");
    }

    private Optional<Set<String>> authenticate(String username, String password) {
        Optional<User> user = users.findByUsername(username).filter(User::isEnabled);
        if (user.isEmpty()) {
            encoder.matches(password, dummyHash); // burn comparable CPU so timing doesn't reveal valid usernames
            return Optional.empty();
        }
        if (!encoder.matches(password, user.get().getPasswordHash())) {
            return Optional.empty();
        }
        return Optional.of(user.get().getRoles().stream().map(Role::name).collect(Collectors.toSet()));
    }

    private TokenResponse issue(String username, Set<String> roles) {
        return new TokenResponse(
                jwt.generate(username, roles, TokenType.ACCESS),
                jwt.generate(username, roles, TokenType.REFRESH),
                "Bearer",
                jwt.accessTtlSeconds());
    }

    private Claims parseOrReject(String token) {
        try {
            return jwt.parse(token);
        } catch (JwtException | IllegalArgumentException e) {
            throw new BadCredentialsException("Invalid refresh token");
        }
    }

    private String revokeQuietly(String token) {
        try {
            Claims c = jwt.parse(token);
            revocations.revoke(c.getId(), c.getExpiration().toInstant());
            return c.getSubject();
        } catch (JwtException | IllegalArgumentException e) {
            return "unknown";
        }
    }
}
