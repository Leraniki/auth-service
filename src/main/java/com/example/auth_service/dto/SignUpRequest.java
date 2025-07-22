package com.example.auth_service.dto;

import com.example.auth_service.model.Role;
import jakarta.validation.constraints.*;
import lombok.Data;
import java.util.Set;

@Data
public class SignUpRequest {
    @NotBlank @Size(min = 3, max = 50)
    private String login;

    @NotBlank @Email
    private String email;

    @NotBlank @Size(min = 6, max = 100)
    private String password;

    private Set<Role> roles;
}