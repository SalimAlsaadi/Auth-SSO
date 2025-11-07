package com.auth.security.auth_security_app.Configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import java.security.KeyStore;

@Configuration
class SigningKeysConfig {

    @Bean
    JWKSource<SecurityContext> jwkSource(
            @Value("${security.keystore.location}") Resource ks,
            @Value("${security.keystore.password}") String password,
            @Value("${security.keystore.key-alias}") String alias) throws Exception {

        KeyStore keyStore = KeyStore.getInstance(ks.getFilename().endsWith(".jks") ? "JKS" : "PKCS12");
        try (var is = ks.getInputStream()) {
            keyStore.load(is, password.toCharArray());
        }

        var key  = (java.security.Key) keyStore.getKey(alias, password.toCharArray());
        var cert = (java.security.cert.X509Certificate) keyStore.getCertificate(alias);

        var rsa = new com.nimbusds.jose.jwk.RSAKey.Builder((java.security.interfaces.RSAPublicKey) cert.getPublicKey())
                .privateKey((java.security.interfaces.RSAPrivateKey) key)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                .keyID(alias) // kid = alias
                .build();

        return new ImmutableJWKSet<>(new JWKSet(rsa));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}

