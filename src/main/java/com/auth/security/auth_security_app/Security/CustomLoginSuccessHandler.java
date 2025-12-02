package com.auth.security.auth_security_app.Security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {
    private static final String ADMIN_ROLE = "ROLE_SAS_ADMIN";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        boolean isAdmin = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).anyMatch(role -> role.equals(ADMIN_ROLE));

        if (isAdmin) {
            response.sendRedirect("/sas-admin/dashboard");

        } else {
            String redirectUri = (String) request.getSession()
                    .getAttribute("SPRING_SECURITY_SAVED_REQUEST");

            if (redirectUri != null) {
                // Spring handle it normally
                response.sendRedirect("/");
            } else {
                response.sendRedirect("/");
            }
        }

    }

}

