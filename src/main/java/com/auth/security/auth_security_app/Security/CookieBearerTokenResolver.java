package com.auth.security.auth_security_app.Security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class CookieBearerTokenResolver implements BearerTokenResolver {

    @Override
    public String resolve(HttpServletRequest request) {

        String path = request.getRequestURI();

        String headerToken = resolveAuthorizationHeaderOnly(request);

        if (StringUtils.hasText(headerToken)) {
            return headerToken;
        }

        if (!path.startsWith("/api/")) {
            return null;
        }

        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (CookieHandler.COOKIE_NAME.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        return null;
    }

    private String resolveAuthorizationHeaderOnly(
            HttpServletRequest request
    ) {
        String auth = request.getHeader("Authorization");

        if (StringUtils.hasText(auth) && auth.startsWith("Bearer ")) {
            return auth.substring(7);
        }

        return null;
    }
}