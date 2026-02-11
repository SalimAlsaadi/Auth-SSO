package com.auth.security.auth_security_app.Security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {

    private final CustomLoginSuccessHandler successHandler;
    private final JwtCookieFilter jwtCookieFilter;
    private final CookieHandler cookieHandler;

    public SecurityConfiguration(CustomLoginSuccessHandler successHandler,
                                 JwtCookieFilter jwtCookieFilter,
                                 CookieHandler cookieHandler) {
        this.successHandler = successHandler;
        this.jwtCookieFilter = jwtCookieFilter;
        this.cookieHandler = cookieHandler;
    }

    // --------------------------------------------------------------------
    // 0) LOGIN PAGE FOR AUTH SERVER UI
    // --------------------------------------------------------------------
    @Bean
    @Order(0)
    public SecurityFilterChain loginChain(HttpSecurity http) throws Exception {

        http
                .securityMatcher(
                        "/auth/login",
                        "/perform_login",
                        "/css/**",
                        "/js/**",
                        "/images/**",
                        "/static/**"
                )
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll()
                )
                .formLogin(form -> form
                        .loginPage("/auth/login")
                        .loginProcessingUrl("/perform_login")
                        .successHandler(successHandler)
                )
                .requestCache(cache -> cache.disable())
                .csrf(csrf -> csrf.disable());

        return http.build();
    }



    // --------------------------------------------------------------------
    // 1) AUTHORIZATION SERVER (PKCE + COOKIE JWT)
    // --------------------------------------------------------------------
    @Bean
    @Order(1)
    public SecurityFilterChain authServerChain(
            HttpSecurity http,
            OidcUserInfoMapper mapper
    ) throws Exception {

        // Applies internal matchers + anyRequest().authenticated()
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
                // Limit this chain strictly to Authorization Server endpoints
                .securityMatcher("/oauth2/**", "/.well-known/**")

                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(end -> end
                        .authorizationRequestConverters(c ->
                                c.add(new OAuth2AuthorizationCodeRequestAuthenticationConverter())
                        )
                )
                .oidc(oidc -> oidc
                        .userInfoEndpoint(u -> u.userInfoMapper(mapper))
                )
                .tokenEndpoint(token -> token
                        .accessTokenResponseHandler((req, res, auth) -> {

                            OAuth2AccessTokenAuthenticationToken tokenAuth =
                                    (OAuth2AccessTokenAuthenticationToken) auth;

                            String jwt = tokenAuth.getAccessToken().getTokenValue();
                            long expiresAt = tokenAuth.getAccessToken()
                                    .getExpiresAt()
                                    .getEpochSecond();

                            cookieHandler.writeTokenCookie(res, jwt, expiresAt);
                        })
                );

        http
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/auth/login")
                        )
                )
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults());

        // ❗ NO authorizeHttpRequests() here
        // ❗ NO anyRequest() here

        return http.build();
    }


    // --------------------------------------------------------------------
    // 2) RESOURCE SERVER (API)
    // --------------------------------------------------------------------
    @Bean
    @Order(2)
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {

        http
                // IMPORTANT: limit this chain to API + Admin only
                .securityMatcher("/admin/**", "/api/**")

                .authorizeHttpRequests(auth -> auth
                        // Public endpoints (if any)
                        .requestMatchers("/", "/error").permitAll()

                        // Admin endpoints
                       // .requestMatchers("/admin/**").hasRole("ADMIN")

                        // Any other API request
                        .anyRequest().permitAll()
                )

                // JWT validation (access token from Authorization Server)
                .oauth2ResourceServer(oauth -> oauth.jwt())

                // Stateless API
                .csrf(csrf -> csrf.disable())

                // CORS for Angular
                .cors(cors -> cors.configurationSource(req -> {
                    CorsConfiguration c = new CorsConfiguration();
                    c.setAllowCredentials(true);
                    c.setAllowedOrigins(List.of("http://localhost:4200"));
                    c.setAllowedHeaders(List.of("*"));
                    c.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    return c;
                }));

        return http.build();
    }


    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder(12);
    }

//    @Bean
//    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbc) {
//        return new com.auth.security.auth_security_app.security.SqlServerRegisteredClientRepository(jdbc);
//    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("https://localhost:9443")
                .build();
    }
}
