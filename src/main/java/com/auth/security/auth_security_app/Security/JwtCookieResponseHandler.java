package com.auth.security.auth_security_app.Security;

import jakarta.servlet.ServletException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AccessTokenResponseAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;

@Component
public class JwtCookieResponseHandler implements AuthenticationSuccessHandler {

    private final CookieHandler cookieHandler;
    private final OAuth2AccessTokenResponseAuthenticationSuccessHandler delegate =
            new OAuth2AccessTokenResponseAuthenticationSuccessHandler();

    public JwtCookieResponseHandler(CookieHandler cookieHandler) {
        this.cookieHandler = cookieHandler;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        if (authentication instanceof OAuth2AccessTokenAuthenticationToken tokenAuth && tokenAuth.getAccessToken() != null && tokenAuth.getAccessToken().getExpiresAt() != null) {

            String jwt = tokenAuth.getAccessToken().getTokenValue();
            Instant exp = tokenAuth.getAccessToken().getExpiresAt();

            long now = Instant.now().getEpochSecond();
            long maxAge = Math.max(0, exp.getEpochSecond() - now);

            cookieHandler.writeTokenCookie(response, jwt, maxAge);
        }

        delegate.onAuthenticationSuccess(request, response, authentication);
    }
}