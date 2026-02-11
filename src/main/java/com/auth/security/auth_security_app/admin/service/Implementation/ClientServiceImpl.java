package com.auth.security.auth_security_app.admin.service.Implementation;

import com.auth.security.auth_security_app.admin.dto.clientDTO.ClientRequestDTO;
import com.auth.security.auth_security_app.admin.dto.clientDTO.ClientResponseDTO;
import com.auth.security.auth_security_app.admin.entity.ClientEntity;
import com.auth.security.auth_security_app.admin.entity.UserEntity;
import com.auth.security.auth_security_app.admin.repository.ClientRepository;
import com.auth.security.auth_security_app.admin.repository.UserRepository;
import com.auth.security.auth_security_app.admin.service.Interface.AuditLogService;
import com.auth.security.auth_security_app.admin.service.Interface.ClientService;
import jakarta.transaction.Transactional;
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
@Transactional
public class ClientServiceImpl implements ClientService {

    private final ClientRepository clientRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;

    /* ============================================================
       CREATE
       ============================================================ */
    @Override
    public ClientResponseDTO create(ClientRequestDTO req) {

        if (clientRepository.findByClientCode(req.getClientCode()).isPresent()) {
            throw new IllegalStateException("Client code already exists");
        }

        if (registeredClientRepository.findByClientId(req.getClientId()) != null) {
            throw new IllegalStateException("OAuth clientId already exists");
        }

        RegisteredClient rc = buildRegisteredClient(req);

        registeredClientRepository.save(rc);

        ClientEntity entity = ClientEntity.builder()
                .clientCode(req.getClientCode())
                .clientName(req.getClientName())
                .clientDescription(req.getClientDescription())
                .oauthClientId(req.getClientId())
                .build();

        clientRepository.save(entity);

        auditLogService.log(
                currentUserId(),
                "CLIENT_CREATE",
                "Client",
                rc.getClientId(),
                "Created client: " + req.getClientName()
        );

        return mapToResponse(rc, entity);
    }

    @Override
    public List<ClientResponseDTO> getAll() {
        return clientRepository.findAll().stream()
                .map(entity -> {
                    RegisteredClient rc = registeredClientRepository
                            .findByClientId(entity.getOauthClientId());

                    if (rc == null) {
                        // Decide: skip, or return partial, or throw.
                        // Best practice: skip broken rows OR log warning.
                        return null;
                    }
                    return mapToResponse(rc, entity);
                })
                .filter(java.util.Objects::nonNull)
                .toList();
    }


    /* ============================================================
       GET ONE
       ============================================================ */
    @Override
    public ClientResponseDTO getById(Integer id) {

        ClientEntity entity = clientRepository.findById(id)
                .orElseThrow(() -> new IllegalStateException("Client not found"));

        RegisteredClient rc =
                registeredClientRepository.findByClientId(entity.getOauthClientId());

        if (rc == null) {
            throw new IllegalStateException("OAuth client configuration missing");
        }

        return mapToResponse(rc, entity);
    }

    /* ============================================================
       UPDATE
       ============================================================ */
    @Override
    public ClientResponseDTO update(String oauthClientId, ClientRequestDTO req) {

        RegisteredClient existing =
                registeredClientRepository.findByClientId(oauthClientId);

        if (existing == null) {
            throw new IllegalStateException("Client not found");
        }

        RegisteredClient updated = rebuildRegisteredClient(existing, req);

        registeredClientRepository.save(updated);

        ClientEntity entity =
                clientRepository.findByOauthClientId(oauthClientId)
                        .orElseThrow(() -> new IllegalStateException("Client entity missing"));

        entity.setClientName(req.getClientName());
        entity.setClientDescription(req.getClientDescription());

        clientRepository.save(entity);

        auditLogService.log(
                currentUserId(),
                "CLIENT_UPDATE",
                "Client",
                oauthClientId,
                "Updated client configuration"
        );

        return mapToResponse(updated, entity);
    }

    /* ============================================================
       BUILD REGISTERED CLIENT (CREATE)
       ============================================================ */
    private RegisteredClient buildRegisteredClient(ClientRequestDTO r) {

        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(r.getClientId())
                .clientIdIssuedAt(java.time.Instant.now())
                .clientName(r.getClientName())

                // Public client + PKCE
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)

                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)

                .redirectUris(uris -> uris.addAll(r.getRedirectUris()))
                .postLogoutRedirectUris(uris -> uris.addAll(r.getPostLogoutRedirectUris()))
                .scopes(sc -> sc.addAll(r.getScopes()))

                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())

                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(false)
                        .build())

                .build();
    }

    /* ============================================================
       BUILD REGISTERED CLIENT (UPDATE – JDBC SAFE)
       ============================================================ */
    private RegisteredClient rebuildRegisteredClient(
            RegisteredClient old,
            ClientRequestDTO r
    ) {

        return RegisteredClient.withId(old.getId())
                .clientId(old.getClientId())
                .clientIdIssuedAt(old.getClientIdIssuedAt())
                .clientName(r.getClientName())

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

    /* ============================================================
       RESPONSE MAPPER
       ============================================================ */
    private ClientResponseDTO mapToResponse(
            RegisteredClient rc,
            ClientEntity entity
    ) {

        ClientResponseDTO dto = new ClientResponseDTO();

        dto.setId(entity.getId());
        dto.setClientCode(entity.getClientCode());
        dto.setClientId(rc.getClientId());
        dto.setClientName(rc.getClientName());
        dto.setClientDescription(entity.getClientDescription());

        dto.setRedirectUris(List.copyOf(rc.getRedirectUris()));
        dto.setPostLogoutRedirectUris(List.copyOf(rc.getPostLogoutRedirectUris()));
        dto.setScopes(List.copyOf(rc.getScopes()));

        dto.setRequireProofKey(rc.getClientSettings().isRequireProofKey());
        dto.setRequireAuthorizationConsent(
                rc.getClientSettings().isRequireAuthorizationConsent()
        );

        dto.setAccessTokenTTL(
                rc.getTokenSettings().getAccessTokenTimeToLive().toSeconds()
        );
        dto.setRefreshTokenTTL(
                rc.getTokenSettings().getRefreshTokenTimeToLive().toSeconds()
        );

        return dto;
    }

    /* ============================================================
       CURRENT USER
       ============================================================ */
    private Long currentUserId() {
        String username = SecurityContextHolder.getContext()
                .getAuthentication()
                .getName();

        return userRepository.findByUsername(username)
                .map(UserEntity::getId)
                .orElse(null);
    }
}
