package com.auth.security.auth_security_app.Configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@Configuration
public class JdbcAuthorizationConfig {

    @Bean
    public JdbcOAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository repo
    ) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, repo);
    }

    @Bean
    public JdbcOAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository repo
    ) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, repo);
    }
}
