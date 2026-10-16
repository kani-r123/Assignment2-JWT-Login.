package com.example.authapp;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthController(
            UserRepository repository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService) {

        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    // Registration
    @PostMapping("/auth/register")
    public ResponseEntity<?> register(
            @RequestBody RegisterRequest request) {

        if (request.name() == null || request.name().isBlank()
                || request.email() == null || request.email().isBlank()
                || request.password() == null
                || request.password().length() < 8) {

            return ResponseEntity.badRequest().body(
                Map.of("message",
                    "Enter name, email and password of at least 8 characters")
            );
        }

        String email = request.email().trim().toLowerCase();

        if (repository.existsByEmail(email)) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(
                Map.of("message", "Email already registered")
            );
        }

        AppUser user = new AppUser();
        user.setName(request.name().trim());
        user.setEmail(email);
        user.setPassword(
            passwordEncoder.encode(request.password())
        );

        repository.save(user);

        return ResponseEntity.status(HttpStatus.CREATED).body(
            Map.of("message", "Registration successful")
        );
    }

    // Login
    @PostMapping("/auth/login")
    public ResponseEntity<?> login(
            @RequestBody LoginRequest request) {

        if (request.email() == null || request.password() == null) {
            return ResponseEntity.badRequest().body(
                Map.of("message", "Email and password are required")
            );
        }

        String email = request.email().trim().toLowerCase();

        AppUser user = repository.findByEmail(email).orElse(null);

        if (user == null
                || !passwordEncoder.matches(
                    request.password(), user.getPassword())) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                Map.of("message", "Invalid email or password")
            );
        }

        String token = jwtService.generateToken(user.getEmail());

        return ResponseEntity.ok(
            Map.of("token", token, "tokenType", "Bearer")
        );
    }

    // Protected profile
    @GetMapping("/users/me")
    public ResponseEntity<?> profile(
            @AuthenticationPrincipal Jwt jwt) {

        AppUser user = repository
                .findByEmail(jwt.getSubject())
                .orElse(null);

        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                Map.of("message", "User not found")
            );
        }

        return ResponseEntity.ok(
            Map.of(
                "id", user.getId(),
                "name", user.getName(),
                "email", user.getEmail()
            )
        );
    }

    public record RegisterRequest(
            String name, String email, String password) {
    }

    public record LoginRequest(
            String email, String password) {
    }
}
