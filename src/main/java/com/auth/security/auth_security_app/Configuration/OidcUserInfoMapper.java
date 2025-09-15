package com.auth.security.auth_security_app.Configuration;

import com.auth.security.auth_security_app.Repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.function.Function;

@Component
public class DefaultOidcUserInfoMapper implements Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {

    private final UserRepository users;

    public DefaultOidcUserInfoMapper(UserRepository users) {
        this.users = users;
    }

    @Override
    public OidcUserInfo apply(OidcUserInfoAuthenticationContext ctx) {
        JwtAuthenticationToken auth = ctx.getAuthentication();
        Jwt jwt = auth.getToken();

        String sub = Optional.ofNullable(jwt.getSubject()).orElse(auth.getName());

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", sub);

        Set<String> scopes = Optional.ofNullable(ctx.getAccessToken().getScopes())
                .orElse(Collections.emptySet());

        String username = auth.getName();

        users.findByUsername(username).ifPresent(user -> {
            if (scopes.contains(OidcScopes.EMAIL)) {
                claims.put("email", user.getUsername());   // if username == email
                claims.put("email_verified", Boolean.TRUE); // set truthfully if you track it
            }
            if (scopes.contains(OidcScopes.PROFILE)) {
                claims.put("preferred_username", user.getUsername());
                // claims.put("name", ...); // optional
            }
            // Custom, non-standard claims (public)
            claims.put("role", user.getRole());
            claims.put("refType", user.getRefType());
            claims.put("refId", user.getRefId());
        });

        return new OidcUserInfo(claims);
    }
}