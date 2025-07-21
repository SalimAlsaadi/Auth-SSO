package com.auth.security.auth_security_app.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {

    @GetMapping("/homePage")
    public ResponseEntity<String> home() {
        return ResponseEntity.ok("✅ Login Successful! Welcome.");
    }

}
