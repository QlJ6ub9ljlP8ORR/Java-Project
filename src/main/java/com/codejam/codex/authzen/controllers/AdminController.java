package com.codejam.codex.authzen.controllers;

import com.codejam.codex.authzen.constants.ApiEndpoint;
import com.codejam.codex.authzen.dtos.inputs.DelegateRequest;
import com.codejam.codex.authzen.dtos.inputs.RoleRequest;
import com.codejam.codex.authzen.dtos.inputs.RoleUpdateRequest;
import com.codejam.codex.authzen.dtos.outputs.AuditLogResponse;
import com.codejam.codex.authzen.dtos.outputs.UpdateUserResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.endpoint.AdminEndpoint;
import com.codejam.codex.authzen.endpoint.AuthEndpoint;
import com.codejam.codex.authzen.responses.AuthzenResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * AdminController handles all endpoints related to administrative actions,
 * such as user management, role assignments, audit log access, and permission delegation.
 * Access to all methods is restricted to users with the ADMIN role.
 */
@RestController
@RequestMapping(ApiEndpoint.ADMIN)
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final AdminEndpoint adminEndpoint;
    private final AuthEndpoint authEndpoint;

    @Autowired
    public AdminController(AdminEndpoint adminEndpoint, AuthEndpoint authEndpoint) {
        this.adminEndpoint = adminEndpoint;
        this.authEndpoint = authEndpoint;
    }

    /**
     * Verifies if the requester is an authenticated admin.
     *
     * @param request HTTP request
     * @return the authenticated admin's username
     */
    private String verifyAdmin(HttpServletRequest request) {
        String username = authEndpoint.getUsername(request);
        if (username == null || !authEndpoint.isAuthenticated(request)) {
            throw new AccessDeniedException("Unauthorized: Invalid or missing token.");
        }

        UserResponse userResponse = authEndpoint.getUserDetails(username);
        if (userResponse == null || !userResponse.getRoles().contains("ROLE_ADMIN")) {
            throw new AccessDeniedException("Forbidden: Insufficient permissions.");
        }

        return username;
    }

    /**
     * List all users.
     */
    @GetMapping(ApiEndpoint.ADMIN_ALL_USERS)
    @PreAuthorize("hasAuthority('VIEW_USER')")
    public ResponseEntity<AuthzenResponse<List<UserResponse>>> getAllUsers(HttpServletRequest request) {
        String username = verifyAdmin(request);
        List<UserResponse> users = adminEndpoint.getAllUsers(username);
        AuthzenResponse<List<UserResponse>> response = new AuthzenResponse<>(users);
        response.setMessage("Users listed successfully.");
        return ResponseEntity.ok(response);
    }

    /**
     * Get a specific user's details.
     */
    @GetMapping(ApiEndpoint.ADMIN_USERS + "/{id}")
    @PreAuthorize("hasAuthority('VIEW_USER')")
    public ResponseEntity<AuthzenResponse<UserResponse>> getUserDetails(@PathVariable("id") Long userId,
                                                                        HttpServletRequest request) {
        verifyAdmin(request); // ensure requester is admin
        UserResponse userResponse = adminEndpoint.getUserById(userId);
        AuthzenResponse<UserResponse> response = new AuthzenResponse<>(userResponse);
        response.setMessage("User details retrieved successfully.");
        return ResponseEntity.ok(response);
    }

    /**
     * Update user roles.
     */
    @PutMapping(ApiEndpoint.ADMIN_USER_ROLES + "/{id}")
    @PreAuthorize("hasAuthority('UPDATE_USER')")
    public ResponseEntity<AuthzenResponse<UpdateUserResponse>> updateUserRole(
            @PathVariable("id") Long userId,
            @Valid @RequestBody RoleUpdateRequest roleUpdateRequest,
            HttpServletRequest request) {

        String username = verifyAdmin(request);
        UpdateUserResponse updated = adminEndpoint.updateUserRoles(userId, roleUpdateRequest, username);
        AuthzenResponse<UpdateUserResponse> response = new AuthzenResponse<>(updated);
        response.setMessage("User roles updated successfully.");
        return ResponseEntity.ok(response);
    }

    /**
     * Create a new system role.
     */
    @PostMapping(ApiEndpoint.ADMIN_ROLES)
    @PreAuthorize("hasAuthority('CREATE_USER')")
    public ResponseEntity<AuthzenResponse<String>> createRole(
            @Valid @RequestBody RoleRequest roleRequest,
            HttpServletRequest request) {

        String username = verifyAdmin(request);
        String created = adminEndpoint.createRole(roleRequest, username);
        AuthzenResponse<String> response = new AuthzenResponse<>();
        response.setMessage(created);
        return ResponseEntity.ok(response);
    }

    /**
     * Get audit logs.
     */
    @GetMapping(ApiEndpoint.ADMIN_AUDIT_LOGS)
    @PreAuthorize("hasAuthority('VIEW_USER')")
    public ResponseEntity<AuthzenResponse<List<AuditLogResponse>>> getAuditLogs(HttpServletRequest request) {
        String username = verifyAdmin(request);
        List<AuditLogResponse> auditLogs = adminEndpoint.getAuditLogs(username);
        AuthzenResponse<List<AuditLogResponse>> response = new AuthzenResponse<>(auditLogs);
        response.setMessage("Audit logs retrieved successfully.");
        return ResponseEntity.ok(response);
    }

    /**
     * Delegate admin permissions to another user.
     */
    @PostMapping(ApiEndpoint.ADMIN_DELEGATE)
    @PreAuthorize("hasAuthority('UPDATE_USER')")
    public ResponseEntity<AuthzenResponse<String>> delegatePermissions(
            @Valid @RequestBody DelegateRequest delegateRequest,
            HttpServletRequest request) {

        String username = verifyAdmin(request);
        String delegated = adminEndpoint.delegatePermissions(delegateRequest, username);
        AuthzenResponse<String> response = new AuthzenResponse<>();
        response.setMessage(delegated);
        return ResponseEntity.ok(response);
    }
}
