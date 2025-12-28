package com.auth.security.auth_security_app.Security;

import com.auth.security.auth_security_app.admin.entity.UserEntity;
import com.auth.security.auth_security_app.admin.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class JwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final UserRepository users;

    public JwtCustomizer(UserRepository users) {
        this.users = users;
    }

    @Transactional
    @Override
    public void customize(JwtEncodingContext context) {

        if (!"access_token".equals(context.getTokenType().getValue())) {
            return;
        }

        Authentication principal = context.getPrincipal();
        String username = principal.getName();

        UserEntity user = users.findByUsername(username).orElse(null);
        if (user == null) return;

        var claims = context.getClaims();

        claims.claim("refType", user.getRefType());
        claims.claim("refId",  String.valueOf(user.getRefId()));
        claims.claim("user", username);

        List<String> roleNames = new ArrayList<>();
        user.getRoles().forEach(r -> roleNames.add(r.getRole().getRoleName()));
        claims.claim("roles", roleNames);
    }
}
