package com.auth.security.auth_security_app.Controller;

import com.auth.security.auth_security_app.admin.dto.user.UserPublicRegistrationDTO;
import com.auth.security.auth_security_app.admin.dto.user.UserResponse;
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
