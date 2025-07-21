package com.auth.security.auth_security_app.Configuration;

import com.auth.security.auth_security_app.Repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

//this class will check if this user has access to clientId and then if has access, will generate new token
@Configuration
public class OAuth2TokenCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(UserRepository userRepository) {
        return context -> {
            if ("access_token".equals(context.getTokenType().getValue())) {
                String username = context.getPrincipal().getName();
                String clientId = context.getRegisteredClient().getClientId();

                var user = userRepository.findByUsername(username)
                        .orElseThrow(() -> new OAuth2AuthenticationException("User not found"));

                if (user.getAllowedClientIds() == null || !user.getAllowedClientIds().contains(clientId)) {
                    throw new OAuth2AuthenticationException("User not allowed to access this client.");
                }

                context.getClaims().claim("role", user.getRole());
                context.getClaims().claim("refType", user.getRefType());
            }
        };
    }
}