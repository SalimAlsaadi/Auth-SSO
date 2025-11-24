package com.auth.security.auth_security_app.Controller;

import com.auth.security.auth_security_app.DATA.DTO.UserDTO;
import com.auth.security.auth_security_app.Services.Interface.RegistrationServiceInterface;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final RegistrationServiceInterface registrationService;

    public AuthController(RegistrationServiceInterface registrationService) {
        this.registrationService = registrationService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody UserDTO dto) {
        registrationService.registerUser(dto);
        return ResponseEntity.ok("User registered successfully");
    }
}
