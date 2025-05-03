package com.codejam.codex.authzen.controllers;

import com.codejam.codex.authzen.constants.ApiEndpoint;
import com.codejam.codex.authzen.dtos.inputs.*;
import com.codejam.codex.authzen.dtos.outputs.TokenResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.responses.AuthzenResponse;
import com.codejam.codex.authzen.endpoint.AuthEndpoint;

import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller responsible for handling HTTP requests related to authentication,
 * including user registration, login, password reset, and OAuth login.
 */
@RestController
@RequestMapping(ApiEndpoint.AUTH)
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final AuthEndpoint authEndpoint;

    public AuthController(AuthEndpoint authEndpoint) {
        this.authEndpoint = authEndpoint;
    }

    @PostMapping(ApiEndpoint.AUTH_REGISTER)
    public ResponseEntity<AuthzenResponse<UserResponse>> register(@Valid @RequestBody RegisterRequest request) {
        try {
            UserResponse userResponse = authEndpoint.registerUser(request);
            AuthzenResponse<UserResponse> response = new AuthzenResponse<>(userResponse);
            response.setMessage("User registered successfully");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Registration failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An internal error occurred during registration"));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_LOGIN)
    public ResponseEntity<AuthzenResponse<TokenResponse>> login(@Valid @RequestBody LoginRequest request) {
        try {
            TokenResponse token = authEndpoint.authenticateUser(request);
            if (token != null) {
                AuthzenResponse<TokenResponse> response = new AuthzenResponse<>(token);
                response.setMessage("User logged in successfully");
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthzenResponse<>(null, false, "Invalid credentials"));
            }
        } catch (Exception e) {
            logger.error("Login failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An internal error occurred during login"));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_OAUTH)
    public ResponseEntity<AuthzenResponse<TokenResponse>> oauthLogin(@Valid @RequestBody OAuthRequest request) {
        try {
            TokenResponse oauthToken = authEndpoint.authenticateOAuth(request);
            if (oauthToken != null) {
                AuthzenResponse<TokenResponse> response = new AuthzenResponse<>(oauthToken);
                response.setMessage("OAuth login successful");
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthzenResponse<>(null, false, "OAuth login failed"));
            }
        } catch (Exception e) {
            logger.error("OAuth login failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An internal error occurred during OAuth login"));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_RESET_REQUEST)
    public ResponseEntity<AuthzenResponse<Void>> resetPasswordRequest(@Valid @RequestBody ResetRequest request) {
        try {
            boolean emailSent = authEndpoint.sendPasswordResetEmail(request);
            if (emailSent) {
                AuthzenResponse<Void> response = new AuthzenResponse<>();
                response.setMessage("Password reset email sent");
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new AuthzenResponse<>(null, false, "Failed to send password reset email"));
            }
        } catch (Exception e) {
            logger.error("Password reset request failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An error occurred while sending reset request"));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_RESET_PASSWORD)
    public ResponseEntity<AuthzenResponse<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        try {
            boolean isPasswordReset = authEndpoint.resetUserPassword(request);
            if (isPasswordReset) {
                AuthzenResponse<Void> response = new AuthzenResponse<>();
                response.setMessage("Password reset successfully");
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new AuthzenResponse<>(null, false, "Failed to reset password"));
            }
        } catch (Exception e) {
            logger.error("Password reset failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An error occurred during password reset"));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_REFRESH)
    public ResponseEntity<AuthzenResponse<TokenResponse>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        try {
            if (request.getRefreshToken() == null || request.getRefreshToken().isBlank()) {
                return ResponseEntity.badRequest()
                        .body(new AuthzenResponse<>(null, false, "Refresh token must not be empty"));
            }
            TokenResponse tokenResponse = authEndpoint.refreshToken(request.getRefreshToken());
            AuthzenResponse<TokenResponse> response = new AuthzenResponse<>(tokenResponse);
            response.setMessage("Token refreshed successfully");
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            logger.error("Token refresh failed", e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthzenResponse<>(null, false, e.getMessage()));
        } catch (Exception e) {
            logger.error("Unexpected error during token refresh", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An internal error occurred during token refresh"));
        }
    }
}
