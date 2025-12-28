package com.auth.security.auth_security_app.admin.service.Implementation;

import com.auth.security.auth_security_app.Security.SqlServerRegisteredClientRepository;
import com.auth.security.auth_security_app.admin.dto.clientDTO.ClientRequest;
import com.auth.security.auth_security_app.admin.dto.clientDTO.ClientResponse;
import com.auth.security.auth_security_app.admin.entity.UserEntity;
import com.auth.security.auth_security_app.admin.repository.UserRepository;
import com.auth.security.auth_security_app.admin.service.Interface.AuditLogService;
import com.auth.security.auth_security_app.admin.service.Interface.ClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ClientServiceImpl implements ClientService {

    private final RegisteredClientRepository repo;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;


    /* ============================================================
       CREATE
       ============================================================ */
    @Override
    public ClientResponse create(ClientRequest req) {

        if (repo.findByClientId(req.getClientId()) != null) {
            throw new RuntimeException("Client already exists");
        }

        RegisteredClient client = mapToEntity(req);
        repo.save(client);

        auditLogService.log(
                currentUserId(),
                "CLIENT_CREATE",
                "Client",
                client.getClientId(),
                "Created client" + client.getClientName()
        );

        return mapToResponse(client);
    }

    /* ============================================================
       GET ONE
       ============================================================ */
    @Override
    public ClientResponse getById(String clientId) {
        RegisteredClient client = repo.findByClientId(clientId);
        if (client == null) {
            throw new RuntimeException("Client not found");
        }
        return mapToResponse(client);
    }

    /* ============================================================
       GET ALL
       ============================================================ */
    @Override
    public List<ClientResponse> getAll() {

        // JdbcTemplate repo does not support findAll(), so we query manually
        // You can add SELECT * FROM oauth2_registered_client easily later.

        throw new UnsupportedOperationException("List all clients not yet implemented");
    }

    /* ============================================================
       UPDATE
       ============================================================ */
    @Override
    public ClientResponse update(String clientId, ClientRequest req) {

        RegisteredClient existing = repo.findByClientId(clientId);
        if (existing == null) {
            throw new RuntimeException("Client not found");
        }

        RegisteredClient updated = mapToUpdatedEntity(existing, req);
        repo.save(updated);

        auditLogService.log(
                currentUserId(),
                "CLIENT_UPDATE",
                "Client",
                clientId,
                "Updated redirect URIs or scopes for this client: " + existing.getClientName()
        );

        return mapToResponse(updated);
    }


    /* ============================================================
       PRIVATE MAPPER - DTO → ENTITY
       ============================================================ */
    private RegisteredClient mapToEntity(ClientRequest r) {

        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(r.getClientId())
                .clientName(r.getClientId())

                // Authentication
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)

                // Grant Types
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)

                // Redirect URIs
                .redirectUris(uris -> uris.addAll(r.getRedirectUris()))
                .postLogoutRedirectUris(uris -> uris.addAll(r.getPostLogoutRedirectUris()))

                // Scopes
                .scopes(sc -> sc.addAll(r.getScopes()))

                // Client Settings
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(r.isRequireProofKey())
                        .requireAuthorizationConsent(false)
                        .build())

                // Token Settings
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(false)
                        .build())

                .build();
    }

    /* ============================================================
       PRIVATE MAPPER - ENTITY → DTO
       ============================================================ */
    private ClientResponse mapToResponse(RegisteredClient c) {

        ClientResponse dto = new ClientResponse();

        dto.setId(c.getId());
        dto.setClientId(c.getClientId());
        dto.setClientName(c.getClientName());

        dto.setRedirectUris(c.getRedirectUris().stream().toList());
        dto.setPostLogoutRedirectUris(c.getPostLogoutRedirectUris().stream().toList());
        dto.setScopes(c.getScopes().stream().toList());

        dto.setRequireProofKey(c.getClientSettings().isRequireProofKey());
        dto.setRequireAuthorizationConsent(c.getClientSettings().isRequireAuthorizationConsent());

        dto.setAccessTokenTTL(c.getTokenSettings().getAccessTokenTimeToLive().toSeconds());
        dto.setRefreshTokenTTL(c.getTokenSettings().getRefreshTokenTimeToLive().toSeconds());

        return dto;
    }

    /* ============================================================
       PRIVATE MAPPER - UPDATE ENTITY WITH REQUEST
       ============================================================ */
    private RegisteredClient mapToUpdatedEntity(RegisteredClient old, ClientRequest r) {

        return RegisteredClient.withId(old.getId())
                .clientId(r.getClientId())
                .clientName(r.getClientId())

                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)

                .redirectUris(uris -> uris.addAll(r.getRedirectUris()))
                .postLogoutRedirectUris(uris -> uris.addAll(r.getPostLogoutRedirectUris()))
                .scopes(sc -> sc.addAll(r.getScopes()))

                .clientSettings(ClientSettings.builder()
                        .requireProofKey(r.isRequireProofKey())
                        .requireAuthorizationConsent(false)
                        .build())

                .tokenSettings(old.getTokenSettings())
                .build();
    }


    private Long currentUserId() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return userRepository.findByUsername(username)
                .map(UserEntity::getId)
                .orElse(null);
    }

}
