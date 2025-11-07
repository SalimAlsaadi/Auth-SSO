package com.auth.security.auth_security_app.Configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.jackson2.SecurityJackson2Modules;

@Configuration
public class JacksonSecurityConfig {


    @Bean
    public ObjectMapper objectMapper(Jackson2ObjectMapperBuilder builder) {
        ObjectMapper mapper = builder.createXmlMapper(false).build();
        mapper.registerModules(SecurityJackson2Modules.getModules(getClass().getClassLoader()));
        return mapper;
    }
}