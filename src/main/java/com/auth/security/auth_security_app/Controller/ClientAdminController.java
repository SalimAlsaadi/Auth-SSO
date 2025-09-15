package com.auth.security.auth_security_app.Controller;

// src/main/java/.../ClientAdminController.java
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

record ClientRequest(
        String clientId,
        List<String> redirectUris,
        List<String> postLogoutRedirectUris,
        List<String> scopes,
        boolean requireProofKey
) {}

@RestController
@RequestMapping("/admin/clients")
@PreAuthorize("hasRole('ADMIN')")
public class ClientAdminController {

    private final RegisteredClientRepository repo;

    public ClientAdminController(RegisteredClientRepository repo) {
        this.repo = repo;
    }

    @PostMapping
    public ResponseEntity<Void> create(@RequestBody ClientRequest r) {
        if (repo.findByClientId(r.clientId()) != null) {
            // 409 is a better signal than 204 for "already exists"
            return ResponseEntity.status(409).build();
        }

        var builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(r.clientId())
                .clientName(r.clientId())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);

        var redirects   = r.redirectUris() == null ? List.<String>of() : r.redirectUris();
        var postLogout  = r.postLogoutRedirectUris() == null ? List.<String>of() : r.postLogoutRedirectUris();
        var scopes      = (r.scopes() == null || r.scopes().isEmpty())
                ? List.of(OidcScopes.OPENID, OidcScopes.PROFILE)
                : r.scopes();

        redirects.forEach(builder::redirectUri);
        postLogout.forEach(builder::postLogoutRedirectUri);
        scopes.forEach(builder::scope);

        var client = builder
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(r.requireProofKey())
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(false)
                        .build())
                .build();

        repo.save(client);
        return ResponseEntity.created(URI.create("/admin/clients/" + r.clientId())).build();
    }
}


