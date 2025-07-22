package com.example.auth_service.service;


import com.example.auth_service.dto.JwtAuthenticationResponse;
import com.example.auth_service.dto.RefreshTokenRequest;
import com.example.auth_service.dto.SignInRequest;
import com.example.auth_service.dto.SignUpRequest;
import com.example.auth_service.model.Role;
import com.example.auth_service.model.TokenBlacklist;
import com.example.auth_service.model.User;
import com.example.auth_service.repository.TokenBlacklistRepository;
import com.example.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final TokenBlacklistRepository tokenBlacklistRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public JwtAuthenticationResponse signup(SignUpRequest request) {
        if (userRepository.existsByLogin(request.getLogin())) {
            throw new IllegalArgumentException("Login already exists");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }

        var user = new User();
        user.setLogin(request.getLogin());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        Set<Role> roles = request.getRoles();
        if (roles == null || roles.isEmpty()) {
            roles = new HashSet<>();
            roles.add(Role.GUEST);
        }
        user.setRoles(roles);

        userRepository.save(user);

        var accessToken = jwtService.generateAccessToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        return JwtAuthenticationResponse.builder().accessToken(accessToken).refreshToken(refreshToken).build();
    }

    public JwtAuthenticationResponse signin(SignInRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getLogin(), request.getPassword()));
        var user = userRepository.findByLogin(request.getLogin())
                .orElseThrow(() -> new IllegalArgumentException("Invalid login or password"));
        var accessToken = jwtService.generateAccessToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        return JwtAuthenticationResponse.builder().accessToken(accessToken).refreshToken(refreshToken).build();
    }

    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest request) {
        String userLogin = jwtService.extractUserName(request.getRefreshToken());
        User user = userRepository.findByLogin(userLogin).orElseThrow(() -> new IllegalArgumentException("User not found"));
        if (jwtService.isTokenValid(request.getRefreshToken(), user)) {
            var accessToken = jwtService.generateAccessToken(user);
            return JwtAuthenticationResponse.builder().accessToken(accessToken).refreshToken(request.getRefreshToken()).build();
        }
        throw new IllegalArgumentException("Invalid refresh token");
    }

    public void logout(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            String jwt = token.substring(7);
            String jti = jwtService.extractJti(jwt);
            tokenBlacklistRepository.save(new TokenBlacklist(jti));
        }
    }
}