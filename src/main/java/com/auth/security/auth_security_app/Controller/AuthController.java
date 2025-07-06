package com.auth.security.auth_security_app.Controller;

import com.auth.security.auth_security_app.DATA.DTO.LandlordRegisterDTO;
import com.auth.security.auth_security_app.Services.Interface.RegistrationServiceInterface;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/auth")
public class AuthController {

    private final RegistrationServiceInterface registrationService;

    @Autowired
    public AuthController(RegistrationServiceInterface registrationService){

        this.registrationService = registrationService;
    }


    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody LandlordRegisterDTO dto) {
        registrationService.registerLandlord(dto);
        return ResponseEntity.ok("User registered successfully");
    }
}