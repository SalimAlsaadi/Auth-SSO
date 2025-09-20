package com.auth.security.auth_security_app.Configuration;

import com.auth.security.auth_security_app.Repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.List;
import java.util.Set;

@Configuration
public class OAuth2TokenCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(UserRepository userRepository) {
        return context -> {
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                return;
            }

            final String username = context.getPrincipal().getName();
            final String clientId = context.getRegisteredClient().getClientId();

            var user = userRepository.findByUsername(username).orElseThrow(
                    () -> new OAuth2AuthenticationException(new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_REQUEST, "User not found", null))
            );

            Set<String> allowed = user.getAllowedClientIds();
            boolean permitted = allowed != null && allowed.contains(clientId);
            if (!permitted) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        OAuth2ErrorCodes.ACCESS_DENIED, "User not allowed to access this client", null));
            }

            var claims = context.getClaims();
            claims.claim("roles", List.of(user.getRole()));
            claims.claim("ref_type", user.getRefType());
            if (user.getRefId() != null) {
                claims.claim("ref_id", user.getRefId());
            }
            claims.claim("client_id", clientId);
        };
    }
}
