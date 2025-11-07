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
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.ForwardedHeaderFilter;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    /* ====================== FILTER CHAIN 1: AUTHORIZATION SERVER ====================== */
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerChain(HttpSecurity http, OidcUserInfoMapper mapper) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(oidc -> oidc.userInfoEndpoint(ui -> ui.userInfoMapper(mapper)));

        http.exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(org.springframework.http.MediaType.TEXT_HTML)
        ));

        http.cors(Customizer.withDefaults());
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt());

        return http.build();
    }

    /* ====================== FILTER CHAIN 2: APPLICATION ENDPOINTS ====================== */
    @Bean
    @Order(2)
    SecurityFilterChain appChain(HttpSecurity http,
                                 UserDetailsService uds,
                                 PasswordEncoder encoder) throws Exception {

        var dao = new DaoAuthenticationProvider();
        dao.setUserDetailsService(uds);
        dao.setPasswordEncoder(encoder);
        http.authenticationProvider(dao);

        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                .requestMatchers("/.well-known/**", "/oauth2/jwks", "/oauth2/authorize", "/oauth2/token").permitAll()
                .requestMatchers("/login", "/error", "/", "/favicon.ico", "/assets/**", "/default-ui.css").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
        );

        http.cors(Customizer.withDefaults());
        http.formLogin(form -> form.defaultSuccessUrl("/", false));
        http.httpBasic(Customizer.withDefaults());

        http.csrf(csrf -> csrf.ignoringRequestMatchers(
                new AntPathRequestMatcher("/api/**"),
                new AntPathRequestMatcher("/admin/**"),
                new AntPathRequestMatcher("/oauth2/token")
        ));

        return http.build();
    }

    /* ====================== CORE SECURITY BEANS ====================== */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    @Primary
    public UserDetailsService userDetailsService(UserRepository userRepository, PasswordEncoder encoder) {
        return new CustomUserDetailsService(userRepository, encoder);
    }

    @Bean
    public ForwardedHeaderFilter forwardedHeaderFilter() {
        return new ForwardedHeaderFilter();
    }

    /* ====================== CORS CONFIGURATION ====================== */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:4200"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /* ====================== CLIENTS (SQL SERVER JDBC) ====================== */
    @Bean
    public RegisteredClientRepository registeredClientRepository(DataSource dataSource) {
        return new JdbcRegisteredClientRepository(new JdbcTemplate(dataSource));
    }

    /* ====================== AUTH SERVER SETTINGS ====================== */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("https://localhost:9443")
                .build();
    }

    /* ====================== JWK + JWT DECODER ====================== */
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
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwk) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwk);
    }

    /* ====================== ACCESS TOKEN CUSTOMIZER ====================== */
    @Bean
    @Primary
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(UserRepository users) {
        return ctx -> {
            if (!"access_token".equals(ctx.getTokenType().getValue())) return;

            var username = ctx.getPrincipal().getName();
            var user = users.findByUsername(username)
                    .orElseThrow(() -> new OAuth2AuthenticationException("User not found"));

            ctx.getClaims().claim("role", user.getRole());
            ctx.getClaims().claim("refType", user.getRefType());
            ctx.getClaims().claim("refId", user.getRefId());
        };
    }
}
