package com.auth.security.auth_security_app.admin.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginPageController {

    @GetMapping("/auth/login")
    public String showLogin(@RequestParam(value = "error", required = false) String error, Model model) {

        if (error != null)
            model.addAttribute("errorMessage", "Invalid username or password");

        return "auth/auth-login";
    }
}


