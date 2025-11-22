package com.auth.security.auth_security_app.Security;

import org.springframework.jdbc.core.JdbcTemplate;
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
import java.util.UUID;
import java.util.stream.Stream;

public class SqlServerRegisteredClientRepository implements RegisteredClientRepository {

    private final JdbcTemplate jdbc;

    public SqlServerRegisteredClientRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void save(RegisteredClient client) {
        if (findById(client.getId()) != null) {
            update(client);
        } else {
            insert(client);
        }
    }

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

    private void insert(RegisteredClient c) {

        Instant issuedAt = c.getClientIdIssuedAt() != null ? c.getClientIdIssuedAt() : Instant.now();

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
                null,
                c.getClientName(),
                join(c.getClientAuthenticationMethods().stream().map(ClientAuthenticationMethod::getValue)),
                join(c.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue)),
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

    private void update(RegisteredClient c) {
        jdbc.update("""
                UPDATE oauth2_registered_client SET
                client_id = ?, client_name = ?,
                client_authentication_methods = ?, authorization_grant_types = ?,
                redirect_uris = ?, post_logout_redirect_uris = ?, scopes = ?,
                require_proof_key = ?, require_authorization_consent = ?,
                access_token_ttl = ?, refresh_token_ttl = ?, reuse_refresh_tokens = ?
                WHERE id = ?
            """,
                c.getClientId(),
                c.getClientName(),
                join(c.getClientAuthenticationMethods().stream().map(ClientAuthenticationMethod::getValue)),
                join(c.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue)),
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

    private RegisteredClient map(ResultSet rs) throws SQLException {

        ClientSettings cs = ClientSettings.builder()
                .requireProofKey(rs.getBoolean("require_proof_key"))
                .requireAuthorizationConsent(rs.getBoolean("require_authorization_consent"))
                .build();

        TokenSettings ts = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofSeconds(rs.getLong("access_token_ttl")))
                .refreshTokenTimeToLive(Duration.ofSeconds(rs.getLong("refresh_token_ttl")))
                .reuseRefreshTokens(rs.getBoolean("reuse_refresh_tokens"))
                .build();

        RegisteredClient.Builder b = RegisteredClient.withId(rs.getString("id"))
                .clientId(rs.getString("client_id"))
                .clientIdIssuedAt(rs.getTimestamp("client_id_issued_at").toInstant())
                .clientName(rs.getString("client_name"))
                .clientSettings(cs)
                .tokenSettings(ts);

        addAll(rs.getString("client_authentication_methods"), v -> b.clientAuthenticationMethod(new ClientAuthenticationMethod(v)));
        addAll(rs.getString("authorization_grant_types"), v -> b.authorizationGrantType(new AuthorizationGrantType(v)));
        addAll(rs.getString("redirect_uris"), b::redirectUri);
        addAll(rs.getString("post_logout_redirect_uris"), b::postLogoutRedirectUri);
        addAll(rs.getString("scopes"), b::scope);

        return b.build();
    }

    private static String join(Stream<String> stream) {
        return String.join(",", stream.toList());
    }

    private static void addAll(String csv, java.util.function.Consumer<String> c) {
        if (csv == null) return;
        for (String x : csv.split(",")) {
            if (!x.isBlank()) c.accept(x.trim());
        }
    }
}
