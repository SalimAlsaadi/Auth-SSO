package com.auth.security.auth_security_app.Security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;


//401 handler
//This will run when:
//        cookie missing
//        cookie expired
//        JWT invalid
//        JWT malformed
//        JWT signature invalid
//        Authorization missing


@Component
public class CookieClearingAuthenticationEntryPoint
        implements AuthenticationEntryPoint {

    private final CookieHandler cookieHandler;
    private final ObjectMapper objectMapper;

    public CookieClearingAuthenticationEntryPoint(
            CookieHandler cookieHandler,
            ObjectMapper objectMapper
    ) {
        this.cookieHandler = cookieHandler;
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException, ServletException {

        cookieHandler.clearAll(response);

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        objectMapper.writeValue(
                response.getWriter(),
                Map.of(
                        "timestamp", Instant.now().toString(),
                        "status", 401,
                        "error", "UNAUTHORIZED",
                        "message", "Session expired or invalid",
                        "path", request.getRequestURI()
                )
        );
    }
}