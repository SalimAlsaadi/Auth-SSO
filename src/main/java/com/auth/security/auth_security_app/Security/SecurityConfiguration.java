package com.auth.security.auth_security_app.Security;

import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {

    @Autowired
    private CustomLoginSuccessHandler customRedirectSuccessHandler;


    @Bean
    @Order(0)
    public SecurityFilterChain loginChain(HttpSecurity http,
                                          CustomLoginSuccessHandler loginSuccessHandler) throws Exception {

        http
                .securityMatcher("/auth/login", "/css/**", "/js/**", "/static/**", "/perform_login")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())

                .formLogin(form -> form
                        .loginPage("/auth/login")
                        .loginProcessingUrl("/perform_login")
                        .successHandler(loginSuccessHandler)
                )

                .csrf(csrf -> csrf.disable());

        return http.build();
    }


    @Bean
    @Order(1)
    SecurityFilterChain authServerChain(HttpSecurity http, OidcUserInfoMapper mapper) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(oidc -> oidc.userInfoEndpoint(c -> c.userInfoMapper(mapper)));

        http.exceptionHandling(ex -> ex
                .authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/auth/login")
                )
        );

        http.oauth2ResourceServer(r -> r.jwt());
        http.csrf(csrf -> csrf.disable());
        http.cors(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain appChain(HttpSecurity http,
                                 UserDetailsService uds,
                                 PasswordEncoder encoder) throws Exception {

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(uds);
        provider.setPasswordEncoder(encoder);
        http.authenticationProvider(provider);

        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/css/**", "/js/**", "/error", "/oauth2/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
        );



        http.csrf(csrf -> csrf.disable());
        http.cors(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new SqlServerRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    AuthorizationServerSettings authSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("https://localhost:9443")
                .build();
    }
}
