package com.auth.security.auth_security_app.Configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import java.security.Key;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class SigningKeysConfig {

    @Bean
    public JWKSource<SecurityContext> jwkSource(
            @Value("${security.keystore.location}") String location,
            @Value("${security.keystore.password}") String password,
            @Value("${security.keystore.key-alias}") String alias
    ) throws Exception {

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (var is = new java.io.FileInputStream(location.replace("file:", ""))) {
            ks.load(is, password.toCharArray());
        }

        Key key = ks.getKey(alias, password.toCharArray());
        var cert = ks.getCertificate(alias);

        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) cert.getPublicKey())
                .privateKey((RSAPrivateKey) key)
                .keyID(alias)
                .build();

        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}
