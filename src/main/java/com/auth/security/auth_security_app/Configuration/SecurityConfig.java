package com.auth.security.auth_security_app.Configuration;

import com.auth.security.auth_security_app.Repository.UserRepository;
import com.auth.security.auth_security_app.Services.Implementation.CustomUserDetailsService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.netty.handler.codec.http.HttpMethod;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
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
import java.util.List;
import java.util.UUID;

@Configuration
public class SecurityConfig {

    // ========= Chain 1: Authorization Server (+ OIDC, + /userinfo as resource server) =========
    @Bean
    @Order(1)
    SecurityFilterChain asChain(HttpSecurity http) throws Exception {
        // Registers the AS endpoints matcher internally
        org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration
                .OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // OIDC (id_token, userinfo, discovery)
        http.getConfigurer(
                org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.class
        ).oidc(Customizer.withDefaults());

        // CORS (reads the CorsConfigurationSource bean below)
        http.cors(Customizer.withDefaults());

        // HTML -> redirect to /login; APIs -> 401
        http.exceptionHandling(e -> e
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new org.springframework.security.web.util.matcher.MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        );

        // /userinfo accepts bearer access tokens
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt());

        return http.build();
    }




    //  ========= Chain 2: App endpoints (login form, registration, etc.) =========
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
                // very important: do NOT protect these, so they are never saved
                .requestMatchers("/.well-known/**", "/oauth2/jwks").permitAll()
                // usual public bits
                .requestMatchers("/login", "/error", "/default-ui.css",
                        "/favicon.ico", "/assets/**", "/index.html").permitAll()
                .requestMatchers(new AntPathRequestMatcher("/", "GET")).permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
        );

        http.cors(Customizer.withDefaults());

        // Keep the default SavedRequest behavior so the AS flow continues correctly
        http.formLogin(form -> form.defaultSuccessUrl("/", false));

        // CSRF ON for form login; ignore for your programmatic APIs
        http.csrf(csrf -> csrf.ignoringRequestMatchers(
                new AntPathRequestMatcher("/api/**"),
                new AntPathRequestMatcher("/admin/**")
        ));

        // Do NOT disable request cache here. The AS chain stores the saved request
        // for /oauth2/authorize; the form login needs to read it to continue the flow.
        // (If you ever disable it, you’ll break the redirect back to the AS flow.)

        return http.build();
    }


    // ========= Core beans =========

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // or your strength
    }

    @Bean
    @Primary
    public UserDetailsService userDetailsService(UserRepository userRepository, PasswordEncoder encoder) {
        return new CustomUserDetailsService(userRepository, encoder);
    }

    // CORS for SPA (dev). No trailing slash; no credentials for token endpoints.
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        var cfg = new CorsConfiguration();
        cfg.setAllowedOriginPatterns(List.of("http://localhost:4200"));
        cfg.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
        cfg.setAllowedHeaders(List.of("Authorization","Content-Type","Accept","Origin","X-Requested-With"));
        cfg.setExposedHeaders(List.of("WWW-Authenticate"));
        cfg.setAllowCredentials(false);             // SPA: no cookies for token calls
        cfg.setMaxAge(Duration.ofHours(1));

        var source = new UrlBasedCorsConfigurationSource();
        // keep it simple: apply to everything; your auth rules still control access
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }


    @Bean
    public RegisteredClientRepository registeredClientRepository(DataSource dataSource) {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }



    @Bean
    public OAuth2AuthorizationService authorizationService(DataSource dataSource, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationService(new JdbcTemplate(dataSource), clients);
    }

    // Consents in MySQL
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, clients);
    }


    // Must match Angular `authority`
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9001")
                .build();
    }

    // ===== DEV keys (ephemeral). For prod, load from a keystore (JKS/PKCS12). =====
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
        return org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration
                .OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}
