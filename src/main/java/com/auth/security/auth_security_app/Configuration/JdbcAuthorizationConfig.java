package com.auth.security.auth_security_app.Configuration;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@Configuration
public class JdbcAuthorizationConfig {

    @Bean
    public LobHandler lobHandler() {
        DefaultLobHandler handler = new DefaultLobHandler();
        handler.setWrapAsLob(true);
        return handler;
    }

    @Bean
    @Primary
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository,
            LobHandler lobHandler
    ) {
        return new CustomJdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository, lobHandler);
    }

}
