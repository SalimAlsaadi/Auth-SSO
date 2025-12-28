package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.Security.CookieHandler;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class LogoutController {

    private final CookieHandler cookieHandler;

    public LogoutController(CookieHandler cookieHandler) {
        this.cookieHandler = cookieHandler;
    }

    /**
     * Browser logout (user comes from login UI)
     */
    @GetMapping("/logout")
    public void logout(HttpServletResponse response) {

        cookieHandler.clear(response);

        response.setHeader("Location", "/auth/login");
        response.setStatus(302);
    }

    /**
     * Angular logout
     * Angular should call this with:
     *  this.http.post('/auth/logout', {}, { withCredentials: true })
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logoutApi(HttpServletResponse response) {

        cookieHandler.clear(response);

        return ResponseEntity.ok(Map.of(
                "message", "Logged out",
                "success", true
        ));
    }
}
