package com.example.sso.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final TokenRevocationStore revocationStore;

    public JwtAuthFilter(JwtService jwtService, TokenRevocationStore revocationStore) {
        this.jwtService = jwtService;
        this.revocationStore = revocationStore;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            try {
                Claims claims = jwtService.parse(header.substring(7));
                if (jwtService.isType(claims, TokenType.ACCESS) && !revocationStore.isRevoked(claims.getId())) {
                    List<GrantedAuthority> authorities = jwtService.rolesOf(claims).stream()
                            .<GrantedAuthority>map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                            .toList();
                    SecurityContextHolder.getContext().setAuthentication(
                            new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities));
                }
            } catch (JwtException | IllegalArgumentException ignored) {
                // invalid/expired token -> stay unauthenticated, entry point returns 401
            }
        }
        chain.doFilter(request, response);
    }
}
