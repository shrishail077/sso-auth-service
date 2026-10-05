package com.example.sso;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.sso.config.JwtProperties;
import com.example.sso.security.JwtService;
import com.example.sso.security.TokenType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import java.time.Duration;
import java.util.Set;
import org.junit.jupiter.api.Test;

class JwtServiceTest {

    private static final String SECRET = "unit-test-secret-unit-test-secret-1234";

    private JwtService service(Duration accessTtl) {
        return new JwtService(new JwtProperties(SECRET, "sso-demo", accessTtl, Duration.ofDays(1)));
    }

    @Test
    void roundTripKeepsSubjectRolesAndType() {
        JwtService svc = service(Duration.ofMinutes(5));
        String token = svc.generate("jdoe", Set.of("MANAGER"), TokenType.ACCESS);

        Claims claims = svc.parse(token);

        assertThat(claims.getSubject()).isEqualTo("jdoe");
        assertThat(svc.rolesOf(claims)).containsExactly("MANAGER");
        assertThat(svc.isType(claims, TokenType.ACCESS)).isTrue();
        assertThat(claims.getId()).isNotBlank();
    }

    @Test
    void expiredTokenIsRejected() {
        JwtService svc = service(Duration.ofSeconds(-5));
        String token = svc.generate("jdoe", Set.of("USER"), TokenType.ACCESS);

        assertThatThrownBy(() -> svc.parse(token)).isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    void tamperedTokenIsRejected() {
        JwtService svc = service(Duration.ofMinutes(5));
        String token = svc.generate("jdoe", Set.of("USER"), TokenType.ACCESS);
        String tampered = token.substring(0, token.length() - 2) + "xx";

        assertThatThrownBy(() -> svc.parse(tampered)).isInstanceOf(JwtException.class);
    }
}
