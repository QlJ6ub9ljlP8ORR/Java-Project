package com.codejam.codex.authzen.configs;

import com.codejam.codex.authzen.models.Role;
import com.codejam.codex.authzen.models.User;
import com.codejam.codex.authzen.models.UserRole;
import com.codejam.codex.authzen.repositories.RoleRepository;
import com.codejam.codex.authzen.repositories.UserRepository;
import com.codejam.codex.authzen.repositories.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;

@Configuration
@RequiredArgsConstructor
public class RoleInitializer {

    private static final Logger logger = LoggerFactory.getLogger(RoleInitializer.class);

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${admin.email}")
    private String adminEmail;

    @Value("${admin.username}")
    private String adminUsername;

    @Value("${admin.password}")
    private String adminPassword;

    @Bean
    CommandLineRunner initializeRolesAndAdmin() {
        return args -> {
            try {
                Role userRole = createRoleIfNotExists("ROLE_USER", "Default user role");
                Role adminRole = createRoleIfNotExists("ROLE_ADMIN", "Administrator with full access");

                if (adminRole == null) {
                    logger.error("Admin role could not be initialized.");
                    throw new IllegalStateException("Admin role initialization failed.");
                }

                createOrUpdateAdminUser(adminRole);
            } catch (Exception e) {
                logger.error("Error during role/admin initialization: {}", e.getMessage(), e);
            }
        };
    }

    private Role createRoleIfNotExists(String name, String description) {
        List<Role> roles = roleRepository.findByName(name);

        if (roles.size() > 1) {
            logger.error("Multiple roles found with the name '{}'", name);
            throw new IllegalStateException("Duplicate roles found with name: " + name);
        }

        if (roles.isEmpty()) {
            Role newRole = Role.builder()
                    .name(name)
                    .description(description)
                    .build();
            Role savedRole = roleRepository.save(newRole);
            logger.info("Created role: {}", name);
            return savedRole;
        }

        return roles.get(0);
    }

    private void createOrUpdateAdminUser(Role adminRole) {
        Optional<User> optionalAdmin = userRepository.findByEmail(adminEmail);

        User admin;
        if (optionalAdmin.isEmpty()) {
            admin = User.builder()
                    .username(adminUsername)
                    .email(adminEmail)
                    .password(passwordEncoder.encode(adminPassword))
                    .isActive(true)
                    .isLocked(false)
                    .createdAt(new Timestamp(System.currentTimeMillis()))
                    .build();

            admin = userRepository.save(admin);
            logger.info("Admin user created: {}", adminEmail);
        } else {
            admin = optionalAdmin.get();
            logger.info("Admin user already exists: {}", adminEmail);
        }

        // Ensure admin has the ROLE_ADMIN assigned
        boolean hasAdminRole = userRoleRepository.existsByUserAndRole(admin, adminRole);
        if (!hasAdminRole) {
            UserRole userRole = new UserRole();
            userRole.setUser(admin);
            userRole.setRole(adminRole);
            userRoleRepository.save(userRole);
            logger.info("Assigned ROLE_ADMIN to admin user: {}", adminEmail);
        } else {
            logger.info("Admin user already has ROLE_ADMIN");
        }
    }
}
