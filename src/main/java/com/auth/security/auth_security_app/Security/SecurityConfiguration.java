package com.auth.security.auth_security_app.Security;

import com.auth.security.auth_security_app.admin.repository.UserRepository;
import com.auth.security.auth_security_app.admin.service.Implementation.ClientAwareAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {

    private final CustomLoginSuccessHandler successHandler;
    private final JwtCookieResponseHandler jwtCookieResponseHandler;
    private final SqlServerRegisteredClientRepository clientRepository;

    public SecurityConfiguration(CustomLoginSuccessHandler successHandler,
                                 JwtCookieResponseHandler jwtCookieResponseHandler,
                                 SqlServerRegisteredClientRepository clientRepository) {
        this.successHandler = successHandler;
        this.jwtCookieResponseHandler = jwtCookieResponseHandler;
        this.clientRepository = clientRepository;
    }

    // ------------------------------------------------
    // 0) LOGIN UI
    // ------------------------------------------------
    @Bean
    @Order(0)
    SecurityFilterChain loginChain(HttpSecurity http, AuthenticationProvider authenticationProvider) throws Exception {

        http.securityMatcher("/auth/login", "/perform_login", "/css/**", "/js/**", "/images/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .formLogin(form -> form
                        .loginPage("/auth/login")
                        .loginProcessingUrl("/perform_login")
                        .successHandler(successHandler)
                )
                .headers(h -> h
                        .frameOptions(f -> f.sameOrigin())
                        .contentTypeOptions(Customizer.withDefaults())
                )
                .cors(Customizer.withDefaults());
        http.authenticationProvider(authenticationProvider);

        return http.build();
    }

    // ------------------------------------------------
    // 1) AUTHORIZATION SERVER
    // ------------------------------------------------
    @Bean
    @Order(1)
    SecurityFilterChain authServerChain(HttpSecurity http,
                                        OidcUserInfoMapper mapper) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        OAuth2AuthorizationServerConfigurer configurer =
                http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);

        configurer
                .oidc(oidc -> oidc.userInfoEndpoint(u -> u.userInfoMapper(mapper)))
                .tokenEndpoint(token -> token
                        .accessTokenResponseHandler(jwtCookieResponseHandler));


        http.securityMatcher(configurer.getEndpointsMatcher())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/auth/login")
                        )
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(configurer.getEndpointsMatcher())
                )
                .headers(h -> h
                        .frameOptions(f -> f.sameOrigin())
                        .contentTypeOptions(Customizer.withDefaults())
                        .httpStrictTransportSecurity(hsts ->
                                hsts.includeSubDomains(true).preload(true)
                        )
                )
                .cors(Customizer.withDefaults());

        return http.build();
    }

    // ------------------------------------------------
    // 2) ADMIN APIs (ROLE_ADMIN required)
    // ------------------------------------------------
    @Bean
    @Order(2)
    SecurityFilterChain adminChain(
            HttpSecurity http,
            CookieBearerTokenResolver resolver,
            JwtAuthConverterConfig jwtAuthConverterConfig
    ) throws Exception {

        http
                .securityMatcher("/api/admin/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/admin/users/service").permitAll()
                        .requestMatchers(HttpMethod.PUT, "/api/admin/users/service").permitAll()
                        .anyRequest().hasRole("SAS_ADMIN")
                )

                .oauth2ResourceServer(oauth -> oauth
                        .bearerTokenResolver(resolver)
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(
                                jwtAuthConverterConfig.jwtAuthenticationConverter()
                        ))
                )
                .exceptionHandling(ex -> ex.authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/auth/login")
                ))
                .sessionManagement(sm ->
                        sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults());

        return http.build();
    }

    // ------------------------------------------------
    // 3) APPLICATION APIs
    // ------------------------------------------------
    @Bean
    @Order(3)
    SecurityFilterChain apiChain(HttpSecurity http,
                                 CookieBearerTokenResolver resolver, JwtAuthConverterConfig jwtAuthConverterConfig) throws Exception {

        http.securityMatcher("/api/**")
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth -> oauth
                        .bearerTokenResolver(resolver)
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverterConfig.jwtAuthenticationConverter()))
                )
                .exceptionHandling(ex -> ex.authenticationEntryPoint((req, res, e) -> {
                    res.setStatus(401);
                    res.setContentType("application/json");
                    res.getWriter().write("{\"error\":\"unauthorized\"}");
                }))
                .sessionManagement(sm ->
                        sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults());

        return http.build();
    }

    // ------------------------------------------------
    // PASSWORD ENCODER
    // ------------------------------------------------
    @Bean
    PasswordEncoder encoder() {
        return new BCryptPasswordEncoder(12);
    }

    // ------------------------------------------------
    // DYNAMIC CORS
    // ------------------------------------------------
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

    // ------------------------------------------------
    // AUTH SERVER SETTINGS
    // ------------------------------------------------
    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("https://localhost:9443")
                .build();
    }


    @Bean
    public AuthenticationProvider authenticationProvider(
            UserRepository userRepository,
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {

        ClientAwareAuthenticationProvider provider =
                new ClientAwareAuthenticationProvider(userRepository);

        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);

        return provider;
    }
}