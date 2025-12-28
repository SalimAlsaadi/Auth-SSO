package com.auth.security.auth_security_app.Security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieHandler {

    private static final String COOKIE_NAME = "SAS_TOKEN";

    public void writeTokenCookie(HttpServletResponse response, String jwt, long expiresAt) {
        long now = System.currentTimeMillis() / 1000;
        long maxAge = Math.max(0, expiresAt - now);

        String cookieHeader =
                "%s=%s; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=%d"
                        .formatted(COOKIE_NAME, jwt, maxAge);

        response.addHeader("Set-Cookie", cookieHeader);
    }

    public void clear(HttpServletResponse response) {
        String expired = ResponseCookie.from(COOKIE_NAME, "")
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .path("/")
                .maxAge(0)
                .build()
                .toString();

        response.addHeader("Set-Cookie", expired);
    }
}
