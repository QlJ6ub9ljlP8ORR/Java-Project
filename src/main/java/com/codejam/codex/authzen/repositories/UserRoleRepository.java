package com.codejam.codex.authzen.repositories;

import com.codejam.codex.authzen.models.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import com.codejam.codex.authzen.models.Role;
import com.codejam.codex.authzen.models.User;

public interface UserRoleRepository extends JpaRepository<UserRole, Long> {
    boolean existsByUserAndRole(User user, Role role);
}
