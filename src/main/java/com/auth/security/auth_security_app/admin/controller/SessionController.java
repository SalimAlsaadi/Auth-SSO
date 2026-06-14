package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.Security.CookieHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth/api")
public class SessionController {

    private final CookieHandler cookieHandler;

    public SessionController(CookieHandler cookieHandler) {
        this.cookieHandler = cookieHandler;
    }

    @PostMapping("/session/destroy")
    public ResponseEntity<Map<String, Object>> destroySession(
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        HttpSession session = request.getSession(false);

        if (session != null) {
            session.invalidate();
        }

        cookieHandler.clearAll(response);

        return ResponseEntity.ok(
                Map.of(
                        "success", true,
                        "message", "Session destroyed"
                )
        );
    }
}
