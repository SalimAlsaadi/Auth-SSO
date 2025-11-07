package com.auth.security.auth_security_app.Configuration;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * Custom SAS AuthorizationService that injects a relaxed, polymorphic, and
 * properly module-registered ObjectMapper into Spring Authorization Server's
 * internal JDBC row/parameter mappers.  This avoids "class not in allowlist"
 * and "cannot construct instance" issues for Long, Instant, URL, etc.
 *
 * Compatible with SAS 1.3 – 1.5 and Boot 3.x.
 */
public class CustomJdbcOAuth2AuthorizationService extends JdbcOAuth2AuthorizationService {

    public CustomJdbcOAuth2AuthorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository,
            LobHandler lobHandler
    ) {
        super(jdbcTemplate, registeredClientRepository, lobHandler);
        injectObjectMapper();
    }

    /**
     * Scans the parent class for any internal mappers that hold an ObjectMapper
     * and replaces them with a secure, fully configured instance.
     */
    private void injectObjectMapper() {
        try {
            /* ---------------------------
             * 1️⃣ Build secure ObjectMapper
             * --------------------------- */
            ObjectMapper mapper = new ObjectMapper();

            // Register Spring Security + SAS modules
            mapper.registerModules(SecurityJackson2Modules.getModules(getClass().getClassLoader()));
            mapper.registerModule(
                    new org.springframework.security.oauth2.server.authorization.jackson2
                            .OAuth2AuthorizationServerJackson2Module()
            );

            // Relaxed polymorphic typing for trusted domain objects
            mapper.activateDefaultTypingAsProperty(
                    mapper.getPolymorphicTypeValidator(),
                    ObjectMapper.DefaultTyping.NON_FINAL,
                    "@class"
            );
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

            /* ---------------------------
             * 2️⃣ Reflectively inject mapper
             * --------------------------- */
            for (var field : JdbcOAuth2AuthorizationService.class.getDeclaredFields()) {
                field.setAccessible(true);
                Object value = field.get(this);
                if (value == null) continue;

                for (var inner : value.getClass().getDeclaredFields()) {
                    if (inner.getType().equals(ObjectMapper.class)) {
                        inner.setAccessible(true);
                        inner.set(value, mapper);
                        System.out.println("✅ Injected custom ObjectMapper into "
                                + value.getClass().getSimpleName());
                    }
                }
            }

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to override SAS ObjectMapper (final best-practice version)", e);
        }
    }
}
