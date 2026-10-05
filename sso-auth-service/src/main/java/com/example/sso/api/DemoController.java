package com.example.sso.api;

import com.example.sso.domain.Role;
import com.example.sso.repo.UserRepository;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Protected resources that demonstrate role-based access control. */
@RestController
@RequestMapping("/api")
public class DemoController {

    public record UserSummary(String username, String email, Set<Role> roles) { }

    private final UserRepository users;

    public DemoController(UserRepository users) {
        this.users = users;
    }

    @GetMapping("/me") // any authenticated user
    public Map<String, Object> me(Authentication auth) {
        List<String> roles = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList();
        return Map.of("username", auth.getName(), "roles", roles);
    }

    @GetMapping("/manager/reports") // MANAGER or ADMIN
    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    public Map<String, String> reports() {
        return Map.of("report", "quarterly-summary", "audience", "MANAGER and above");
    }

    @GetMapping("/admin/users") // ADMIN only
    @PreAuthorize("hasRole('ADMIN')")
    public List<UserSummary> listUsers() {
        return users.findAll().stream()
                .map(u -> new UserSummary(u.getUsername(), u.getEmail(), u.getRoles()))
                .toList();
    }
}
