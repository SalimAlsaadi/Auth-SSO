package com.auth.security.auth_security_app.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.stream.Collectors;

@Configuration
public class JwtAuthConverterConfig {

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {

        JwtGrantedAuthoritiesConverter scopes = new JwtGrantedAuthoritiesConverter(); // scope -> SCOPE_x

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            var authorities = new java.util.ArrayList<>(scopes.convert(jwt));

            Object rolesClaim = jwt.getClaims().get("roles");
            if (rolesClaim instanceof java.util.Collection<?> roles) {
                authorities.addAll(
                        roles.stream()
                                .map(String::valueOf)
                                .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                                .map(org.springframework.security.core.authority.SimpleGrantedAuthority::new)
                                .collect(Collectors.toList())
                );
            }

            return authorities;
        });

        return converter;
    }
}
