package com.auth.security.auth_security_app.Configuration;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.settings.ConfigurationSettingNames;

import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Duration;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Function;

public class SqlServerRegisteredClientRepository implements RegisteredClientRepository {

    private static final String TBL = "[dbo].[oauth2_registered_client]";

    private static final String SELECT_BASE = """
        SELECT id, client_id, client_id_issued_at, client_secret, client_secret_expires_at,
               client_name, client_authentication_methods, authorization_grant_types,
               redirect_uris, post_logout_redirect_uris, scopes,
               client_settings, token_settings
          FROM """ + TBL + " ";

    private final JdbcTemplate jdbc;
    private final ObjectMapper om;

    public SqlServerRegisteredClientRepository(JdbcTemplate jdbc, ObjectMapper om) {
        this.jdbc = jdbc;
        this.om = om;
    }

    @Override
    public void save(RegisteredClient rc) {
        RegisteredClient existing = findById(rc.getId());
        if (existing == null) insert(rc); else update(rc);
    }

    @Override
    public RegisteredClient findById(String id) {
        var list = jdbc.query(SELECT_BASE + "WHERE id = ?", rowMapper(), id);
        return list.isEmpty() ? null : list.get(0);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        var list = jdbc.query(SELECT_BASE + "WHERE client_id = ?", rowMapper(), clientId);
        return list.isEmpty() ? null : list.get(0);
    }

    private void insert(RegisteredClient rc) {
        final String sql = """
        INSERT INTO """ + TBL + """
        ( id, client_id, client_id_issued_at, client_secret, client_secret_expires_at,
          client_name, client_authentication_methods, authorization_grant_types,
          redirect_uris, post_logout_redirect_uris, scopes, client_settings, token_settings )
        VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )
        """;

        byte[] clientSettings = toBytesJson(rc.getClientSettings().getSettings());
        byte[] tokenSettings  = toBytesJson(rc.getTokenSettings().getSettings());

        jdbc.update(con -> {
            PreparedStatement ps = con.prepareStatement(sql);
            int i = 1;
            ps.setString(i++, rc.getId());
            ps.setString(i++, rc.getClientId());
            if (rc.getClientIdIssuedAt() != null) ps.setTimestamp(i++, Timestamp.from(rc.getClientIdIssuedAt())); else ps.setNull(i++, Types.TIMESTAMP);
            ps.setString(i++, rc.getClientSecret());
            if (rc.getClientSecretExpiresAt() != null) ps.setTimestamp(i++, Timestamp.from(rc.getClientSecretExpiresAt())); else ps.setNull(i++, Types.TIMESTAMP);
            ps.setString(i++, rc.getClientName());
            ps.setString(i++, join(rc.getClientAuthenticationMethods().stream().map(ClientAuthenticationMethod::getValue)));
            ps.setString(i++, join(rc.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue)));
            ps.setString(i++, join(rc.getRedirectUris().stream()));
            ps.setString(i++, join(rc.getPostLogoutRedirectUris().stream()));
            ps.setString(i++, join(rc.getScopes().stream()));
            ps.setBytes(i++, clientSettings);   // VARBINARY(MAX)
            ps.setBytes(i++, tokenSettings);    // VARBINARY(MAX)
            return ps;
        });
    }

    private void update(RegisteredClient rc) {
        final String sql = """
        UPDATE """ + TBL + """
        SET client_id = ?,
            client_id_issued_at = ?,
            client_secret = ?,
            client_secret_expires_at = ?,
            client_name = ?,
            client_authentication_methods = ?,
            authorization_grant_types = ?,
            redirect_uris = ?,
            post_logout_redirect_uris = ?,
            scopes = ?,
            client_settings = ?,
            token_settings = ?
        WHERE id = ?
        """;

        byte[] clientSettings = toBytesJson(rc.getClientSettings().getSettings());
        byte[] tokenSettings  = toBytesJson(rc.getTokenSettings().getSettings());

        jdbc.update(con -> {
            PreparedStatement ps = con.prepareStatement(sql);
            int i = 1;
            ps.setString(i++, rc.getClientId());
            if (rc.getClientIdIssuedAt() != null) ps.setTimestamp(i++, Timestamp.from(rc.getClientIdIssuedAt())); else ps.setNull(i++, Types.TIMESTAMP);
            ps.setString(i++, rc.getClientSecret());
            if (rc.getClientSecretExpiresAt() != null) ps.setTimestamp(i++, Timestamp.from(rc.getClientSecretExpiresAt())); else ps.setNull(i++, Types.TIMESTAMP);
            ps.setString(i++, rc.getClientName());
            ps.setString(i++, join(rc.getClientAuthenticationMethods().stream().map(ClientAuthenticationMethod::getValue)));
            ps.setString(i++, join(rc.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue)));
            ps.setString(i++, join(rc.getRedirectUris().stream()));
            ps.setString(i++, join(rc.getPostLogoutRedirectUris().stream()));
            ps.setString(i++, join(rc.getScopes().stream()));
            ps.setBytes(i++, clientSettings);
            ps.setBytes(i++, tokenSettings);
            ps.setString(i++, rc.getId());
            return ps;
        });
    }

    private RowMapper<RegisteredClient> rowMapper() {
        return (ResultSet rs, int rowNum) -> {
            // 1) Read JSON blobs (bytes -> Map)
            Map<String, Object> clientSettingsRaw = fromBytesJson(rs.getBytes("client_settings"));
            Map<String, Object> tokenSettingsRaw  = fromBytesJson(rs.getBytes("token_settings"));

            // 2) Build typed ClientSettings
            ClientSettings.Builder cs = ClientSettings.builder();
            Boolean requirePkce    = getBoolean(clientSettingsRaw, ConfigurationSettingNames.Client.REQUIRE_PROOF_KEY, "requireProofKey");
            Boolean requireConsent = getBoolean(clientSettingsRaw, ConfigurationSettingNames.Client.REQUIRE_AUTHORIZATION_CONSENT, "requireAuthorizationConsent");
            if (requirePkce != null)    cs.requireProofKey(requirePkce);
            if (requireConsent != null) cs.requireAuthorizationConsent(requireConsent);
            // Preserve unknown keys (optional)
            cs.settings(m -> m.putAll(mergeUnknown(clientSettingsRaw, Set.of(
                    ConfigurationSettingNames.Client.REQUIRE_PROOF_KEY,
                    ConfigurationSettingNames.Client.REQUIRE_AUTHORIZATION_CONSENT
            ))));

            // 3) Build typed TokenSettings
            TokenSettings.Builder ts = TokenSettings.builder();
            Duration authCodeTtl   = getDuration(tokenSettingsRaw, ConfigurationSettingNames.Token.AUTHORIZATION_CODE_TIME_TO_LIVE, "authorizationCodeTimeToLive");
            Duration accessTtl     = getDuration(tokenSettingsRaw, ConfigurationSettingNames.Token.ACCESS_TOKEN_TIME_TO_LIVE, "accessTokenTimeToLive");
            Duration refreshTtl    = getDuration(tokenSettingsRaw, ConfigurationSettingNames.Token.REFRESH_TOKEN_TIME_TO_LIVE, "refreshTokenTimeToLive");
            Duration deviceCodeTtl = getDuration(tokenSettingsRaw, ConfigurationSettingNames.Token.DEVICE_CODE_TIME_TO_LIVE, "deviceCodeTimeToLive");
            Boolean reuseRefresh   = getBoolean (tokenSettingsRaw, ConfigurationSettingNames.Token.REUSE_REFRESH_TOKENS, "reuseRefreshTokens");

            if (authCodeTtl   != null) ts.authorizationCodeTimeToLive(authCodeTtl);
            if (accessTtl     != null) ts.accessTokenTimeToLive(accessTtl);
            if (refreshTtl    != null) ts.refreshTokenTimeToLive(refreshTtl);
            if (deviceCodeTtl != null) ts.deviceCodeTimeToLive(deviceCodeTtl);
            if (reuseRefresh  != null) ts.reuseRefreshTokens(reuseRefresh);
            // Preserve unknown keys (optional)
            ts.settings(m -> m.putAll(mergeUnknown(tokenSettingsRaw, Set.of(
                    ConfigurationSettingNames.Token.AUTHORIZATION_CODE_TIME_TO_LIVE,
                    ConfigurationSettingNames.Token.ACCESS_TOKEN_TIME_TO_LIVE,
                    ConfigurationSettingNames.Token.REFRESH_TOKEN_TIME_TO_LIVE,
                    ConfigurationSettingNames.Token.DEVICE_CODE_TIME_TO_LIVE,
                    ConfigurationSettingNames.Token.REUSE_REFRESH_TOKENS
            ))));

            // 4) Build RegisteredClient
            RegisteredClient.Builder b = RegisteredClient.withId(rs.getString("id"))
                    .clientId(rs.getString("client_id"))
                    .clientName(rs.getString("client_name"))
                    .clientSettings(cs.build())
                    .tokenSettings(ts.build());

            Timestamp issuedAt = rs.getTimestamp("client_id_issued_at");
            if (issuedAt != null) b.clientIdIssuedAt(issuedAt.toInstant());

            String secret = rs.getString("client_secret");
            if (secret != null) b.clientSecret(secret);

            Timestamp secretExp = rs.getTimestamp("client_secret_expires_at");
            if (secretExp != null) b.clientSecretExpiresAt(secretExp.toInstant());

            addAll(b::clientAuthenticationMethod, rs.getString("client_authentication_methods"), ClientAuthenticationMethod::new);
            addAll(b::authorizationGrantType,     rs.getString("authorization_grant_types"),   AuthorizationGrantType::new);
            addAll(b::redirectUri,                rs.getString("redirect_uris"),               s -> s);
            addAll(b::postLogoutRedirectUri,      rs.getString("post_logout_redirect_uris"),   s -> s);
            addAll(b::scope,                      rs.getString("scopes"),                      s -> s);

            return b.build();
        };
    }

    // ---------- helpers ----------

    private static String join(java.util.stream.Stream<String> s) {
        // stable join for deterministic diffs/logs
        return String.join(",", s.sorted().toList());
    }

    private byte[] toBytesJson(Map<String, Object> map) {
        try {
            String json = om.writeValueAsString(map == null ? Map.of() : map);
            return json.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot serialize settings", e);
        }
    }

    private Map<String, Object> fromBytesJson(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return new LinkedHashMap<>();
        try {
            String json = new String(bytes, StandardCharsets.UTF_8);
            return om.readValue(json, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException("Cannot deserialize settings", e);
        }
    }

    private static Duration getDuration(Map<String, Object> m, String... keys) {
        for (String k : keys) {
            Object v = m.get(k);
            if (v == null) continue;
            if (v instanceof Duration d) return d;
            if (v instanceof String s && !s.isBlank()) return Duration.parse(s.trim()); // expects ISO-8601, e.g. "PT5M"
            if (v instanceof Number n) return Duration.ofSeconds(n.longValue());
        }
        return null;
    }

    private static Boolean getBoolean(Map<String, Object> m, String... keys) {
        for (String k : keys) {
            Object v = m.get(k);
            if (v == null) continue;
            if (v instanceof Boolean b) return b;
            if (v instanceof String s)  return Boolean.parseBoolean(s.trim());
            if (v instanceof Number n)  return n.intValue() != 0;
        }
        return null;
    }

    /** Keep unknown keys, but drop ones we re-typed into the builder. */
    private static Map<String, Object> mergeUnknown(Map<String, Object> raw, Set<String> knownKeys) {
        if (raw == null || raw.isEmpty()) return Map.of();
        Map<String, Object> out = new LinkedHashMap<>();
        raw.forEach((k, v) -> { if (!knownKeys.contains(k)) out.put(k, v); });
        return out;
    }

    private <T> void addAll(Consumer<T> consumer, String csv, Function<String, T> mapper) {
        if (csv == null || csv.isBlank()) return;
        for (String p : csv.split(",")) {
            String v = p.trim();
            if (!v.isEmpty()) consumer.accept(mapper.apply(v));
        }
    }
}
