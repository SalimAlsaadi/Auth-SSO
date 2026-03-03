package com.auth.security.auth_security_app.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {

    private final CustomLoginSuccessHandler successHandler;
    private final JwtCookieResponseHandler jwtCookieResponseHandler;
    private final SqlServerRegisteredClientRepository clientRepository;

    public SecurityConfiguration(CustomLoginSuccessHandler successHandler,
                                 JwtCookieResponseHandler jwtCookieResponseHandler, SqlServerRegisteredClientRepository clientRepository) {
        this.successHandler = successHandler;
        this.jwtCookieResponseHandler = jwtCookieResponseHandler;
        this.clientRepository = clientRepository;
    }

    // 0) LOGIN UI (public)
    @Bean
    @Order(0)
    SecurityFilterChain loginChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/auth/login", "/perform_login", "/css/**", "/js/**", "/images/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .formLogin(form -> form
                        .loginPage("/auth/login")
                        .loginProcessingUrl("/perform_login")
                        .successHandler(successHandler)
                )
                .headers(h -> h
                        .xssProtection(x -> x.disable()) // modern browsers rely on CSP
                        .contentTypeOptions(c -> {})
                        .frameOptions(f -> f.sameOrigin())
                );

        return http.build();
    }

    // 1) AUTHORIZATION SERVER (OIDC/OAuth2)
    @Bean
    @Order(1)
    SecurityFilterChain authServerChain(HttpSecurity http,
                                        OidcUserInfoMapper mapper) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        OAuth2AuthorizationServerConfigurer configurer =
                http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);

        configurer
                .oidc(oidc -> oidc.userInfoEndpoint(u -> u.userInfoMapper(mapper)))
                .tokenEndpoint(token -> token.accessTokenResponseHandler(jwtCookieResponseHandler));

        http.securityMatcher(configurer.getEndpointsMatcher())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login"))
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers(configurer.getEndpointsMatcher()))
                .headers(h -> h
                        .contentTypeOptions(c -> {})
                        .frameOptions(f -> f.sameOrigin())
                        // enable HSTS only in HTTPS production (you can gate by profile)
                        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).preload(true))
                );

        http
                .cors(Customizer.withDefaults());

        return http.build();
    }

    // 2) ADMIN UI (browser) -> redirect to login
    @Bean
    @Order(2)
    SecurityFilterChain adminChain(HttpSecurity http, JwtCookieFilter jwtCookieFilter) throws Exception {

        http.securityMatcher("/admin/**")
                .addFilterBefore(jwtCookieFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .exceptionHandling(ex -> ex.authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/auth/login")
                ))
                // If admin has forms, prefer CSRF ENABLED and use proper CSRF tokens
                .csrf(csrf -> csrf.disable());

        http
                .cors(Customizer.withDefaults());

        return http.build();
    }

    // 3) API -> 401 (no redirect)
    @Bean
    @Order(3)
    SecurityFilterChain apiChain(HttpSecurity http, JwtCookieFilter jwtCookieFilter) throws Exception {

        http.securityMatcher("/api/**")
                .addFilterBefore(jwtCookieFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .exceptionHandling(ex -> ex.authenticationEntryPoint((req, res, e) -> {
                    res.setStatus(401);
                    res.setContentType("application/json");
                    res.getWriter().write("{\"error\":\"unauthorized\"}");
                }))
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable());

        return http.build();
    }

    @Bean
    PasswordEncoder encoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public JwtCookieFilter jwtCookieFilter(org.springframework.security.oauth2.jwt.JwtDecoder jwtDecoder) {
        return new JwtCookieFilter(jwtDecoder);
    }


    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        return request -> {

            String origin = request.getHeader("Origin");

            CorsConfiguration config = new CorsConfiguration();
            config.setAllowCredentials(true);
            config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
            config.setAllowedHeaders(List.of("*"));
            config.setExposedHeaders(List.of("Authorization"));

            if (origin == null) {
                return config;
            }

            List<String> allowedOrigins = clientRepository.findAllAllowedOrigins();

            if (allowedOrigins.contains(origin)) {
                config.setAllowedOrigins(List.of(origin));
            }

            return config;
        };
    }


    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                // PRODUCTION: set to real public issuer URL
                .issuer("https://localhost:9443")
                .build();
    }
}