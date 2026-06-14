package com.auth.security.auth_security_app.Security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;


//403 handler
@Component
public class CookieClearingAccessDeniedHandler
        implements AccessDeniedHandler {

    private final CookieHandler cookieHandler;
    private final ObjectMapper objectMapper;

    public CookieClearingAccessDeniedHandler(
            CookieHandler cookieHandler,
            ObjectMapper objectMapper
    ) {
        this.cookieHandler = cookieHandler;
        this.objectMapper = objectMapper;
    }

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException
    ) throws IOException, ServletException {

        /*
         * Optional:
         * For normal "valid user but no role" cases,
         * you may NOT want to clear the cookie.
         *
         * But if your business requirement is:
         * "any 403 means session must be removed",
         * keep this line.
         */
        cookieHandler.clearAll(response);

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        objectMapper.writeValue(
                response.getWriter(),
                Map.of(
                        "timestamp", Instant.now().toString(),
                        "status", 403,
                        "error", "FORBIDDEN",
                        "message", "Access denied",
                        "path", request.getRequestURI()
                )
        );
    }
}