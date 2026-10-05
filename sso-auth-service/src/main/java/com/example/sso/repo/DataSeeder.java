package com.example.sso.repo;

import com.example.sso.domain.Role;
import com.example.sso.domain.User;
import java.util.Set;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/** Seeds demo users, one per role. Demo credentials only - never ship defaults like this. */
@Component
public class DataSeeder implements CommandLineRunner {

    private final UserRepository users;
    private final PasswordEncoder encoder;

    public DataSeeder(UserRepository users, PasswordEncoder encoder) {
        this.users = users;
        this.encoder = encoder;
    }

    @Override
    public void run(String... args) {
        seed("user1", "User@123", Role.USER);
        seed("manager1", "Manager@123", Role.MANAGER);
        seed("admin1", "Admin@123", Role.ADMIN);
    }

    private void seed(String username, String password, Role role) {
        if (users.findByUsername(username).isEmpty()) {
            users.save(new User(username, username + "@example.com", encoder.encode(password), Set.of(role)));
        }
    }
}
