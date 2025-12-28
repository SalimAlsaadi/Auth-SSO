package com.auth.security.auth_security_app.Security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final HttpSessionRequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            org.springframework.security.core.Authentication authentication
    ) throws IOException, ServletException {

        // 1️⃣ Try to restore saved OAuth2 request (VERY IMPORTANT)
        var saved = requestCache.getRequest(request, response);

        if (saved != null) {
            // Continue OAuth2 Authorization Code flow
            response.sendRedirect(saved.getRedirectUrl());
            return;
        }

        // 2️⃣ If no saved request, fallback to normal login
        response.sendRedirect("/");  // admin dashboard for SAS
    }
}
