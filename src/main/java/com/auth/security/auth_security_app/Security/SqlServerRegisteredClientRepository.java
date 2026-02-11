package com.auth.security.auth_security_app.security;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.stream.Stream;

@Repository
@RequiredArgsConstructor
public class SqlServerRegisteredClientRepository implements RegisteredClientRepository {

    private final JdbcTemplate jdbc;

    /* ============================================================
       SAVE
       ============================================================ */
    @Override
    public void save(RegisteredClient client) {

        RegisteredClient existing = findById(client.getId());

        if (existing == null) {
            insert(client);
        } else {
            update(client);
        }
    }

    /* ============================================================
       FIND
       ============================================================ */
    @Override
    public RegisteredClient findById(String id) {
        return jdbc.query(
                "SELECT * FROM oauth2_registered_client WHERE id = ?",
                rs -> rs.next() ? map(rs) : null,
                id
        );
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return jdbc.query(
                "SELECT * FROM oauth2_registered_client WHERE client_id = ?",
                rs -> rs.next() ? map(rs) : null,
                clientId
        );
    }

    /* ============================================================
       INSERT
       ============================================================ */
    private void insert(RegisteredClient c) {

        Instant issuedAt = c.getClientIdIssuedAt() != null
                ? c.getClientIdIssuedAt()
                : Instant.now();

        jdbc.update("""
            INSERT INTO oauth2_registered_client
            (id, client_id, client_id_issued_at,
             client_secret, client_secret_expires_at,
             client_name, client_authentication_methods,
             authorization_grant_types, redirect_uris,
             post_logout_redirect_uris, scopes,
             require_proof_key, require_authorization_consent,
             access_token_ttl, refresh_token_ttl, reuse_refresh_tokens)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
                c.getId(),
                c.getClientId(),
                Timestamp.from(issuedAt),
                c.getClientSecret(),
                c.getClientSecretExpiresAt() != null
                        ? Timestamp.from(c.getClientSecretExpiresAt())
                        : null,
                c.getClientName(),
                join(c.getClientAuthenticationMethods().stream()
                        .map(ClientAuthenticationMethod::getValue)),
                join(c.getAuthorizationGrantTypes().stream()
                        .map(AuthorizationGrantType::getValue)),
                join(c.getRedirectUris().stream()),
                join(c.getPostLogoutRedirectUris().stream()),
                join(c.getScopes().stream()),
                c.getClientSettings().isRequireProofKey(),
                c.getClientSettings().isRequireAuthorizationConsent(),
                c.getTokenSettings().getAccessTokenTimeToLive().toSeconds(),
                c.getTokenSettings().getRefreshTokenTimeToLive().toSeconds(),
                c.getTokenSettings().isReuseRefreshTokens()
        );
    }

    /* ============================================================
       UPDATE
       ============================================================ */
    private void update(RegisteredClient c) {

        jdbc.update("""
            UPDATE oauth2_registered_client SET
                client_id = ?,
                client_name = ?,
                client_authentication_methods = ?,
                authorization_grant_types = ?,
                redirect_uris = ?,
                post_logout_redirect_uris = ?,
                scopes = ?,
                require_proof_key = ?,
                require_authorization_consent = ?,
                access_token_ttl = ?,
                refresh_token_ttl = ?,
                reuse_refresh_tokens = ?
            WHERE id = ?
        """,
                c.getClientId(),
                c.getClientName(),
                join(c.getClientAuthenticationMethods().stream()
                        .map(ClientAuthenticationMethod::getValue)),
                join(c.getAuthorizationGrantTypes().stream()
                        .map(AuthorizationGrantType::getValue)),
                join(c.getRedirectUris().stream()),
                join(c.getPostLogoutRedirectUris().stream()),
                join(c.getScopes().stream()),
                c.getClientSettings().isRequireProofKey(),
                c.getClientSettings().isRequireAuthorizationConsent(),
                c.getTokenSettings().getAccessTokenTimeToLive().toSeconds(),
                c.getTokenSettings().getRefreshTokenTimeToLive().toSeconds(),
                c.getTokenSettings().isReuseRefreshTokens(),
                c.getId()
        );
    }

    /* ============================================================
       MAP RESULTSET → REGISTEREDCLIENT
       ============================================================ */
    private RegisteredClient map(ResultSet rs) throws SQLException {

        ClientSettings clientSettings = ClientSettings.builder()
                .requireProofKey(rs.getBoolean("require_proof_key"))
                .requireAuthorizationConsent(rs.getBoolean("require_authorization_consent"))
                .build();

        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofSeconds(rs.getLong("access_token_ttl")))
                .refreshTokenTimeToLive(Duration.ofSeconds(rs.getLong("refresh_token_ttl")))
                .reuseRefreshTokens(rs.getBoolean("reuse_refresh_tokens"))
                .build();

        RegisteredClient.Builder builder =
                RegisteredClient.withId(rs.getString("id"))
                        .clientId(rs.getString("client_id"))
                        .clientIdIssuedAt(
                                rs.getTimestamp("client_id_issued_at") != null
                                        ? rs.getTimestamp("client_id_issued_at").toInstant()
                                        : Instant.now()
                        )
                        .clientName(rs.getString("client_name"))
                        .clientSettings(clientSettings)
                        .tokenSettings(tokenSettings);

        addAll(rs.getString("client_authentication_methods"),
                v -> builder.clientAuthenticationMethod(new ClientAuthenticationMethod(v)));

        addAll(rs.getString("authorization_grant_types"),
                v -> builder.authorizationGrantType(new AuthorizationGrantType(v)));

        addAll(rs.getString("redirect_uris"), builder::redirectUri);
        addAll(rs.getString("post_logout_redirect_uris"), builder::postLogoutRedirectUri);
        addAll(rs.getString("scopes"), builder::scope);

        return builder.build();
    }

    /* ============================================================
       HELPERS
       ============================================================ */
    private static String join(Stream<String> stream) {
        return String.join(",", stream.toList());
    }

    private static void addAll(String csv, java.util.function.Consumer<String> consumer) {
        if (csv == null || csv.isBlank()) return;
        for (String v : csv.split(",")) {
            consumer.accept(v.trim());
        }
    }
}
