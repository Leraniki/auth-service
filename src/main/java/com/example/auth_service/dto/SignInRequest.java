package com.example.auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class SignInRequest {
    @NotBlank
    private String login;

    @NotBlank
    private String password;
}