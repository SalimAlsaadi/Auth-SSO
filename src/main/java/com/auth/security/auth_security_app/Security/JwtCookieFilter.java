package com.auth.security.auth_security_app.Security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtCookieFilter extends OncePerRequestFilter {

    private final CookieHandler cookieHandler;

    public JwtCookieFilter(CookieHandler cookieHandler) {
        this.cookieHandler = cookieHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        filterChain.doFilter(request, response);

        OAuth2AccessTokenAuthenticationToken token =
                (OAuth2AccessTokenAuthenticationToken)
                        request.getAttribute(OAuth2AccessTokenAuthenticationToken.class.getName());

        if (token != null && token.getAccessToken() != null) {
            String jwt = token.getAccessToken().getTokenValue();
            long exp = token.getAccessToken().getExpiresAt().getEpochSecond();

            cookieHandler.writeTokenCookie(response, jwt, exp);
        }
    }
}
