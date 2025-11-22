package com.auth.security.auth_security_app.Controller;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/admin/clients")
@PreAuthorize("permitAll()")
public class ClientAdminController {

    private final RegisteredClientRepository repo;

    public ClientAdminController(RegisteredClientRepository repo) {
        this.repo = repo;
    }

    @PostMapping
    public ResponseEntity<Void> create(@RequestBody ClientRequest r) {

        if (repo.findByClientId(r.clientId()) != null) {
            return ResponseEntity.status(409).build();
        }

        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(r.clientId())
                .clientName(r.clientId())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUris(uris -> uris.addAll(r.redirectUris()))
                .postLogoutRedirectUris(uris -> uris.addAll(r.postLogoutRedirectUris()))
                .scopes(sc -> sc.addAll(
                        r.scopes().isEmpty() ?
                                List.of(OidcScopes.OPENID, OidcScopes.PROFILE) :
                                r.scopes())
                )
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


    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ClientRequest(
            @JsonProperty("clientId") String clientId,
            @JsonProperty("redirectUris") List<String> redirectUris,
            @JsonProperty("postLogoutRedirectUris") List<String> postLogoutRedirectUris,
            @JsonProperty("scopes") List<String> scopes,
            @JsonProperty("requireProofKey") boolean requireProofKey
    ) {}
}
