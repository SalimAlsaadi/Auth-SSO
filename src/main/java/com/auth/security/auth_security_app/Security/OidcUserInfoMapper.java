package com.auth.security.auth_security_app.Security;

import com.auth.security.auth_security_app.Repository.UserRepository;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class OidcUserInfoMapper implements java.util.function.Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {

    private final UserRepository users;

    public OidcUserInfoMapper(UserRepository users) {
        this.users = users;
    }

    @Override
    public OidcUserInfo apply(OidcUserInfoAuthenticationContext ctx) {

        String username = ctx.getAuthorization().getPrincipalName();
        Set<String> scopes = ctx.getAuthorization().getAuthorizedScopes();

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put(StandardClaimNames.SUB, username);

        users.findByUsername(username).ifPresent(u -> {

            if (scopes.contains(OidcScopes.EMAIL)) {
                claims.put(StandardClaimNames.EMAIL, u.getUsername());
                claims.put(StandardClaimNames.EMAIL_VERIFIED, true);
            }

            if (scopes.contains(OidcScopes.PROFILE)) {
                claims.put(StandardClaimNames.PREFERRED_USERNAME, u.getUsername());
            }

            claims.put("refType", u.getRefType());
            claims.put("refId", u.getRefId());

            List<String> roles = new ArrayList<>();
            u.getRoles().forEach(r -> roles.add(r.getRoleName()));
            claims.put("roles", roles);
        });

        return new OidcUserInfo(normalizeMap(claims));
    }

    private Map<String, Object> normalizeMap(Map<String, Object> source) {
        Map<String, Object> safe = new LinkedHashMap<>();
        source.forEach((k, v) -> safe.put(k, normalize(v)));
        return safe;
    }

    private Object normalize(Object v) {
        if (v instanceof Map<?, ?> m) {
            Map<String, Object> safe = new LinkedHashMap<>();
            m.forEach((k, val) -> safe.put(String.valueOf(k), normalize(val)));
            return safe;
        }
        if (v instanceof List<?> list) {
            List<Object> safe = new ArrayList<>();
            for (Object item : list) safe.add(normalize(item));
            return safe;
        }
        return v;
    }
}
