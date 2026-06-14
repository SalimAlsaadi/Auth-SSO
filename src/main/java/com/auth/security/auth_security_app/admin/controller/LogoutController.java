package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.Security.CookieHandler;
import com.auth.security.auth_security_app.Security.SqlServerRegisteredClientRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/auth")
public class LogoutController {

    private static final String DEFAULT_LOGOUT_REDIRECT = "/auth/login";
    private static final String JSESSIONID = "JSESSIONID";

    private final CookieHandler cookieHandler;
    private final SqlServerRegisteredClientRepository registeredClientRepository;

    public LogoutController(
            CookieHandler cookieHandler,
            SqlServerRegisteredClientRepository registeredClientRepository
    ) {
        this.cookieHandler = cookieHandler;
        this.registeredClientRepository = registeredClientRepository;
    }

    /**
     * Browser / OIDC logout.
     *
     * Example:
     * GET /auth/logout?client_id=AQARK-client&post_logout_redirect_uri=http://localhost:4200/
     */
    @GetMapping("/logout")
    public void logout(
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "post_logout_redirect_uri", required = false) String requestedRedirectUri,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {

        clearServerAuthentication(request, response);

        String redirectUri = resolveLogoutRedirectUri(clientId, requestedRedirectUri);

        response.sendRedirect(redirectUri);
    }

    /**
     * API logout for SPA / Angular.
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logoutApi(HttpServletRequest request, HttpServletResponse response) {

        clearServerAuthentication(request, response);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Logged out"
        ));
    }

    private void clearServerAuthentication(
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        // Clear custom JWT / SAS cookie
        cookieHandler.clearAll(response);

        // Clear Spring Security context
        SecurityContextHolder.clearContext();

        // Invalidate server-side session
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        // Expire JSESSIONID cookie
        Cookie sessionCookie = new Cookie(JSESSIONID, null);
        sessionCookie.setPath("/");
        sessionCookie.setHttpOnly(true);
        sessionCookie.setSecure(request.isSecure());
        sessionCookie.setMaxAge(0);
        response.addCookie(sessionCookie);
    }

    private String resolveLogoutRedirectUri(
            String clientId,
            String requestedRedirectUri
    ) {

        if (clientId == null || clientId.isBlank()) {
            return DEFAULT_LOGOUT_REDIRECT;
        }

        var registeredClient = registeredClientRepository.findByClientId(clientId);

        if (registeredClient == null) {
            return DEFAULT_LOGOUT_REDIRECT;
        }

        Set<String> allowedRedirectUris = registeredClient.getPostLogoutRedirectUris();

        if (allowedRedirectUris == null || allowedRedirectUris.isEmpty()) {
            return DEFAULT_LOGOUT_REDIRECT;
        }

        if (
                requestedRedirectUri != null &&
                        !requestedRedirectUri.isBlank() &&
                        allowedRedirectUris.contains(requestedRedirectUri)
        ) {
            return requestedRedirectUri;
        }

        return allowedRedirectUris.iterator().next();
    }
}