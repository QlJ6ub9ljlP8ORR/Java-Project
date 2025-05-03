package com.codejam.codex.authzen.security;

import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Main Security Configuration class that:
 * - Configures JWT-based OAuth2 authentication using HS256
 * - Sets global CORS and CSRF policies
 * - Applies secure HTTP headers
 * - Secures endpoints with role-based access
 * - Implements proper exception handling
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@SecurityScheme(
        name = "Bearer Authentication",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        scheme = "bearer"
)
public class SecurityConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfiguration.class);
    private static final int MINIMUM_SECRET_LENGTH = 32; // 256 bits min for HS256

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${cors.allowed-origins:http://localhost:8080}")
    private String[] allowedOrigins;

    private final Environment environment;

    public SecurityConfiguration(Environment environment) {
        this.environment = environment;
    }

    /**
     * Custom JWT Authentication Converter to extract roles from token claims.
     * Roles must be defined in the "roles" claim without any prefix.
     * Safely handles null claim values to prevent NPEs.
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<GrantedAuthority> authorities = new ArrayList<>();

            try {
                // Safely handle potential null claims
                List<String> roles = jwt.getClaimAsStringList("roles");
                if (roles != null) {
                    roles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
                }

                List<String> permissions = jwt.getClaimAsStringList("permissions");
                if (permissions != null) {
                    permissions.forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
                }
            } catch (Exception e) {
                log.warn("Error extracting authorities from JWT: {}", e.getMessage());
                // Return empty authorities instead of failing completely
            }

            return authorities;
        });

        return converter;
    }

    /**
     * Main Security Filter Chain configuration.
     * - Enables stateless session
     * - Disables CSRF (suitable for REST APIs)
     * - Applies JWT-based OAuth2 security
     * - Configures public and protected routes
     * - Adds secure headers and CORS support
     * - Implements proper exception handling for auth failures
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(corsFilter(), CorsFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/authenticate/auth/register",
                                "/api/authenticate/auth/login",
                                "/api/authenticate/auth/oauth",
                                "/api/authenticate/auth/reset-request",
                                "/api/authenticate/auth/reset-password",
                                "/api/authenticate/user/refresh",
                                "/api/authenticate/auth/logout",
                                "/css/**",
                                "/js/**",
                                "/swagger-ui/**",
                                "/reset-password/**",
                                "/api/authenticate/health",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/swagger-resources/**",
                                "/webjars/**",
                                "/error"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                                .decoder(jwtDecoder())
                        )
                        .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                        .accessDeniedHandler(new BearerTokenAccessDeniedHandler())
                )
                .headers(headers -> {
                    headers
                            .contentSecurityPolicy(csp -> csp.policyDirectives(
                                    "default-src 'self'; " +
                                    "script-src 'self' 'unsafe-inline'; " +
                                    "style-src 'self' 'unsafe-inline'; " +
                                    "img-src 'self' data:; " +
                                    "connect-src 'self'"
                            ))
                            .frameOptions(frame -> frame.deny())
                            .addHeaderWriter(new StaticHeadersWriter("X-Content-Type-Options", "nosniff"))
                            .httpStrictTransportSecurity(hsts -> hsts
                                    .includeSubDomains(true)
                                    .maxAgeInSeconds(31536000))
                            .referrerPolicy(referrer -> referrer
                                    .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.SAME_ORIGIN));
                })
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint((request, response, authException) -> {
                            log.error("Authentication failure: {}", authException.getMessage());
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                            response.setContentType("application/json");
                            response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Authentication failed\"}");
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            log.error("Access denied: {}", accessDeniedException.getMessage());
                            response.setStatus(HttpStatus.FORBIDDEN.value());
                            response.setContentType("application/json");
                            response.getWriter().write("{\"error\":\"Forbidden\",\"message\":\"Access denied\"}");
                        })
                );

        return http.build();
    }

    /**
     * Configures a CORS filter allowing specified origins, headers, and common methods.
     * Uses environment-specific configuration to restrict CORS in production.
     */
    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        
        // Apply environment-specific CORS configuration
        if (Arrays.asList(environment.getActiveProfiles()).contains("dev")) {
            log.warn("Using development CORS configuration with relaxed constraints");
            config.setAllowedOrigins(Collections.singletonList("*"));
        } else {
            log.info("Using production CORS configuration with specific allowed origins");
            config.setAllowedOrigins(Arrays.asList(allowedOrigins));
        }

        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList(
                "Authorization", 
                "Content-Type", 
                "X-Requested-With", 
                "Accept", 
                "Origin", 
                "Access-Control-Request-Method", 
                "Access-Control-Request-Headers"
        ));
        config.setExposedHeaders(Arrays.asList("Authorization", "Content-Disposition"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        
        return new CorsFilter(source);
    }

    /**
     * BCrypt password encoder bean for secure password hashing.
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // Higher strength (12) for better security
    }

    /**
     * Custom JWT token validator that ensures claims meet the application requirements.
     */
    @Bean
    public OAuth2TokenValidator<Jwt> jwtValidator() {
        return new OAuth2TokenValidator<Jwt>() {
            @Override
            public OAuth2TokenValidatorResult validate(Jwt jwt) {
                // Validate subject is present
                if (jwt.getSubject() == null || jwt.getSubject().isEmpty()) {
                    OAuth2Error error = new OAuth2Error("invalid_token", "The JWT must contain a subject claim", null);
                    return OAuth2TokenValidatorResult.failure(error);
                }
                
                // Add other custom validations as needed
                return OAuth2TokenValidatorResult.success();
            }
        };
    }

    /**
     * Configures JWT decoder for HS256 symmetric key with proper validation.
     * Ensures key length is compliant with HS256 requirement (>= 256 bits).
     * Adds custom token validation.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        
        // Validate secret key length 
        if (keyBytes.length < MINIMUM_SECRET_LENGTH) {
            log.error("JWT secret is too short! It must be at least 256 bits (32 bytes) for HS256");
            throw new IllegalArgumentException("JWT secret does not meet the minimum length requirement");
        }
        
        SecretKey key = new SecretKeySpec(keyBytes, "HmacSHA256");
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withSecretKey(key).build();
        
        // Combine default validators with custom validators
        OAuth2TokenValidator<Jwt> defaultValidators = JwtValidators.createDefault();
        OAuth2TokenValidator<Jwt> customValidator = jwtValidator();
        
        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(defaultValidators, customValidator));
        
        return jwtDecoder;
    }
}