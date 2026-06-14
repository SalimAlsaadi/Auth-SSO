package com.auth.security.auth_security_app.Security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieHandler {

    public static final String COOKIE_NAME = "SAS_TOKEN";
    public static final String SESSION_COOKIE_NAME = "JSESSIONID";

    public void writeTokenCookie(
            HttpServletResponse response,
            String jwt,
            long maxAgeSeconds
    ) {

        ResponseCookie cookie = ResponseCookie.from(COOKIE_NAME, jwt)
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .path("/")
                .maxAge(maxAgeSeconds)
                .build();

        response.addHeader("Set-Cookie", cookie.toString());
    }

    public void clearTokenCookie(HttpServletResponse response) {

        ResponseCookie expired = ResponseCookie.from(COOKIE_NAME, "")
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .path("/")
                .maxAge(0)
                .build();

        response.addHeader("Set-Cookie", expired.toString());
    }

    public void clearSessionCookie(HttpServletResponse response) {

        ResponseCookie expired = ResponseCookie.from(SESSION_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .path("/")
                .maxAge(0)
                .build();

        response.addHeader("Set-Cookie", expired.toString());
    }

    public void clearAll(HttpServletResponse response) {
        clearTokenCookie(response);
        clearSessionCookie(response);
    }
}