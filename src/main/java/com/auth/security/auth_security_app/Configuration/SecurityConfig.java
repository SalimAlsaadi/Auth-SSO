package com.auth.security.auth_security_app.Configuration;

import com.auth.security.auth_security_app.Repository.UserRepository;
import com.auth.security.auth_security_app.Services.Implementation.CustomUserDetailsService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;

@Configuration
@EnableMethodSecurity(prePostEnabled = true) // for @PreAuthorize etc.
public class  SecurityConfig {

    // --------------------------- Filter chain 1: Authorization Server ---------------------------
    @Bean
    @Order(1)
    SecurityFilterChain asChain(HttpSecurity http, OidcUserInfoMapper mapper) throws Exception {
        org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration
                .OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(
                org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.class
        ).oidc(oidc -> oidc.userInfoEndpoint(ui -> ui.userInfoMapper(mapper)));

        http.cors(Customizer.withDefaults());
        http.exceptionHandling(e -> e.defaultAuthenticationEntryPointFor(
                new org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint("/login"),
                new org.springframework.security.web.util.matcher.MediaTypeRequestMatcher(org.springframework.http.MediaType.TEXT_HTML)
        ));
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt());
        return http.build();
    }



    // --------------------------- Filter chain 2: Your app endpoints ---------------------------
    @Bean
    @Order(2)
    SecurityFilterChain appChain(HttpSecurity http,
                                 UserDetailsService uds,
                                 PasswordEncoder enc) throws Exception {

        var dao = new DaoAuthenticationProvider();
        dao.setUserDetailsService(uds);
        dao.setPasswordEncoder(enc);
        http.authenticationProvider(dao);

        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                // public assets / landing
                .requestMatchers("/login", "/error", "/default-ui.css",
                        "/favicon.ico", "/assets/**", "/index.html", "/").permitAll()
                // admin API
                .requestMatchers("/admin/**").hasRole("ADMIN")
                // everything else must be authenticated
                .anyRequest().authenticated()
        );

        http.cors(Customizer.withDefaults());

        // Good default: after successful login, go to saved request (AS flow) or "/" if nothing is saved
        http.formLogin(form -> form.defaultSuccessUrl("/", false));

        // CSRF ON for form login; ignore for programmatic APIs
        http.csrf(csrf -> csrf.ignoringRequestMatchers(
                new AntPathRequestMatcher("/api/**"),
                new AntPathRequestMatcher("/admin/**")
        ));

        return http.build();
    }

    // --------------------------- Core beans ---------------------------

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    @Primary
    public UserDetailsService userDetailsService(UserRepository userRepository, PasswordEncoder encoder) {
        return new CustomUserDetailsService(userRepository, encoder);
    }

    // Simple dev CORS: allow your Angular app; no cookies for token calls
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        var cfg = new CorsConfiguration();
        cfg.setAllowedOriginPatterns(List.of("http://localhost:4200"));
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"));
        cfg.setExposedHeaders(List.of("WWW-Authenticate"));
        cfg.setAllowCredentials(Boolean.valueOf(true));
        cfg.setMaxAge(Duration.ofHours(1));

        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }

    // JDBC persistence for Registered Clients
    @Bean
    public RegisteredClientRepository registeredClientRepository(DataSource dataSource) {
        return new JdbcRegisteredClientRepository(new JdbcTemplate(dataSource));
    }

    // JDBC persistence for issued authorizations (codes/tokens)
    @Bean
    public OAuth2AuthorizationService authorizationService(DataSource dataSource, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationService(new JdbcTemplate(dataSource), clients);
    }

    // JDBC persistence for consents
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
                                                                         RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, clients);
    }

    // Issuer must match Angular's `authority`
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9001")
                .build();
    }

    // ----- DEV keys (ephemeral). For PROD, load from JKS/PKCS12 or JWKS file on disk. -----
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        var kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        var rsa = new RSAKey.Builder((RSAPublicKey) kp.getPublic())
                .privateKey((RSAPrivateKey) kp.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
        var jwkSet = new JWKSet(rsa);
        return (selector, ctx) -> selector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }


    // --------------------------- Access-token customizer (per client permissions) ---------------------------

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(UserRepository userRepository) {
        return context -> {
            // add claims / enforce policies only for access tokens
            if (!"access_token".equals(context.getTokenType().getValue())) return;

            String username = context.getPrincipal().getName();
            String clientId = context.getRegisteredClient().getClientId();

            var user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new org.springframework.security.oauth2.core.OAuth2AuthenticationException("User not found"));

            // Enforce per-user allowed clients
            if (user.getAllowedClientIds() == null || !user.getAllowedClientIds().contains(clientId)) {
                throw new org.springframework.security.oauth2.core.OAuth2AuthenticationException("User not allowed to access this client.");
            }

            // Attach useful custom claims to the access token
            context.getClaims().claim("role", user.getRole());
            context.getClaims().claim("refType", user.getRefType());
            context.getClaims().claim("refId", user.getRefId());
        };
    }
}
