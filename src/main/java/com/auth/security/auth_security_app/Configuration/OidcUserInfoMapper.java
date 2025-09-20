// src/main/java/.../OidcUserInfoMapper.java
package com.auth.security.auth_security_app.Configuration;

import com.auth.security.auth_security_app.Repository.UserRepository;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.function.Function;

import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;

@Component
public class OidcUserInfoMapper
        implements Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {

    private final UserRepository users;

    public OidcUserInfoMapper(UserRepository users) {
        this.users = users;
    }

    @Override
    public OidcUserInfo apply(OidcUserInfoAuthenticationContext ctx) {
        try {
            // MUST match the principal for this authorization
            String subject = ctx.getAuthorization().getPrincipalName();
            Set<String> scopes = ctx.getAuthorization().getAuthorizedScopes();

            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put(StandardClaimNames.SUB, subject);

            boolean wantsEmail   = scopes.contains(OidcScopes.EMAIL);
            boolean wantsProfile = scopes.contains(OidcScopes.PROFILE);

            if (wantsEmail || wantsProfile) {
                users.findByUsername(subject).ifPresent(u -> {
                    if (wantsEmail) {
                        claims.put(StandardClaimNames.EMAIL, u.getUsername());   // if username==email
                        claims.put(StandardClaimNames.EMAIL_VERIFIED, Boolean.TRUE); // set real value if you store it
                    }
                    if (wantsProfile) {
                        claims.put(StandardClaimNames.PREFERRED_USERNAME, u.getUsername());
                        // optionally: NAME, GIVEN_NAME, FAMILY_NAME, UPDATED_AT, ...
                    }
                    // Custom public claims
                    claims.put("role",   u.getRole());
                    claims.put("refType",u.getRefType());
                    claims.put("refId",  u.getRefId());
                });
            }

            return new OidcUserInfo(claims);
        } catch (Exception ex) {
            // Never let exceptions surface (would become 400)
            return new OidcUserInfo(Map.of(StandardClaimNames.SUB,
                    ctx.getAuthorization().getPrincipalName()));
        }
    }
}
