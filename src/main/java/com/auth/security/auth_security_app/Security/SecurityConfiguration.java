package com.auth.security.auth_security_app.Security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
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
                .securityMatcher("/auth/login", "/perform_login", "/css/**", "/js/**", "/static/**", "/images/**")
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll()
                )
                .formLogin(form -> form
                        .loginPage("/auth/login")
                        .loginProcessingUrl("/perform_login")
                        .successHandler(successHandler)
                )
                .requestCache(cache -> cache.disable())  // ❌ Do NOT save requests in this chain
                .csrf(cs -> cs.disable());

        return http.build();
    }



    // --------------------------------------------------------------------
    // 1) AUTHORIZATION SERVER (PKCE + COOKIE JWT)
    // --------------------------------------------------------------------
    @Bean
    @Order(1)
    public SecurityFilterChain authServerChain(HttpSecurity http, OidcUserInfoMapper mapper) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(end -> end
                        .authorizationRequestConverters(c -> c.add(new OAuth2AuthorizationCodeRequestAuthenticationConverter()))
                )
                .oidc(oidc -> oidc.userInfoEndpoint(u -> u.userInfoMapper(mapper)))
                .tokenEndpoint(token -> token
                        .accessTokenResponseHandler((req, res, auth) -> {
                            OAuth2AccessTokenAuthenticationToken tokenAuth =
                                    (OAuth2AccessTokenAuthenticationToken) auth;

                            String jwt = tokenAuth.getAccessToken().getTokenValue();
                            long expiresAt = tokenAuth.getAccessToken().getExpiresAt().getEpochSecond();

                            cookieHandler.writeTokenCookie(res, jwt, expiresAt);
                        })
                );

        http.logout(l -> l
                .logoutUrl("/auth/logout")
                .logoutSuccessHandler((req, res, auth) -> {
                    cookieHandler.clear(res);
                    res.setStatus(HttpServletResponse.SC_OK);
                })
        );

        http.exceptionHandling(ex -> ex.authenticationEntryPoint(
                new LoginUrlAuthenticationEntryPoint("/auth/login")
        ));

        http.oauth2ResourceServer(r -> r.jwt());
        http.csrf(cs -> cs.disable());
        http.cors(Customizer.withDefaults());
        http.requestCache(cache -> cache.requestCache(new HttpSessionRequestCache()));

        return http.build();
    }


    // --------------------------------------------------------------------
    // 2) RESOURCE SERVER (API)
    // --------------------------------------------------------------------
    @Bean
    @Order(2)
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/","/oauth2/**","/error").permitAll()
                .anyRequest().authenticated()
        );

        http.oauth2ResourceServer(r -> r.jwt());
        http.csrf(cs -> cs.disable());

        http.cors(cors -> cors.configurationSource(req -> {
            CorsConfiguration c = new CorsConfiguration();
            c.setAllowCredentials(true);
            c.setAllowedOrigins(List.of("http://localhost:4200"));
            c.setAllowedHeaders(List.of("*"));
            c.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
            return c;
        }));

        return http.build();
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbc) {
        return new SqlServerRegisteredClientRepository(jdbc);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("https://localhost:9443")
                .build();
    }
}
