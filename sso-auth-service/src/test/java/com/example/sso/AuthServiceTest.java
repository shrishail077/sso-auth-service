package com.example.sso;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.sso.audit.AuditService;
import com.example.sso.auth.AuthService;
import com.example.sso.auth.LoginRequest;
import com.example.sso.auth.TokenResponse;
import com.example.sso.domain.Role;
import com.example.sso.domain.User;
import com.example.sso.repo.UserRepository;
import com.example.sso.security.JwtService;
import com.example.sso.security.TokenRevocationStore;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

class AuthServiceTest {

    private UserRepository users;
    private PasswordEncoder encoder;
    private JwtService jwt;
    private AuditService audit;
    private AuthService service;

    @BeforeEach
    void setUp() {
        users = mock(UserRepository.class);
        encoder = mock(PasswordEncoder.class);
        jwt = mock(JwtService.class);
        audit = mock(AuditService.class);
        service = new AuthService(users, encoder, jwt, new TokenRevocationStore(), audit);
    }

    @Test
    void validLoginIssuesTokensAndAudits() {
        User user = new User("manager1", "m@example.com", "hash", Set.of(Role.MANAGER));
        when(users.findByUsername("manager1")).thenReturn(Optional.of(user));
        when(encoder.matches("pw", "hash")).thenReturn(true);
        when(jwt.generate(any(), any(), any())).thenReturn("token");
        when(jwt.accessTtlSeconds()).thenReturn(900L);

        TokenResponse res = service.login(new LoginRequest("manager1", "pw"));

        assertThat(res.accessToken()).isEqualTo("token");
        assertThat(res.expiresInSeconds()).isEqualTo(900L);
        verify(audit).record("LOGIN_SUCCESS", "manager1", "password login");
    }

    @Test
    void unknownUserFailsWithGenericMessageAndAudits() {
        when(users.findByUsername("ghost")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.login(new LoginRequest("ghost", "pw")))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Invalid credentials");
        verify(audit).record("LOGIN_FAILURE", "ghost", "bad credentials");
    }

    @Test
    void wrongPasswordFailsWithSameGenericMessage() {
        User user = new User("user1", "u@example.com", "hash", Set.of(Role.USER));
        when(users.findByUsername("user1")).thenReturn(Optional.of(user));
        when(encoder.matches("wrong", "hash")).thenReturn(false);

        assertThatThrownBy(() -> service.login(new LoginRequest("user1", "wrong")))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Invalid credentials");
        verify(audit).record("LOGIN_FAILURE", "user1", "bad credentials");
    }
}
