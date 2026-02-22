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

        ResponseCookie cookie = ResponseCookie.from(COOKIE_NAME, jwt)
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .path("/")
                .maxAge(maxAge)
                .build();

        response.addHeader("Set-Cookie", cookie.toString());
    }

    public void clear(HttpServletResponse response) {

        ResponseCookie expired = ResponseCookie.from(COOKIE_NAME, "")
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .path("/")
                .maxAge(0)
                .build();

        response.addHeader("Set-Cookie", expired.toString());
    }
}
