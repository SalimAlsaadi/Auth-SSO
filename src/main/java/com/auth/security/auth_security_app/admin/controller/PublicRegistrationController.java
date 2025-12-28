package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.admin.dto.userDTO.UserPublicRegistrationDTO;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserResponse;
import com.auth.security.auth_security_app.admin.service.Interface.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/public")
@RequiredArgsConstructor
public class PublicRegistrationController {

    private final UserService userService;

    @PostMapping("/register")
    public UserResponse registerUser(@Valid @RequestBody UserPublicRegistrationDTO dto) {
        return userService.registerExternalUser(dto);
    }
}
