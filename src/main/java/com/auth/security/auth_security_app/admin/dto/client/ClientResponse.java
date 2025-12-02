package com.auth.security.auth_security_app.admin.dto.client;

import lombok.Data;
import java.util.List;

@Data
public class ClientResponse {
    private String id;
    private String clientId;
    private String clientName;

    private List<String> redirectUris;
    private List<String> postLogoutRedirectUris;

    private List<String> grantTypes;
    private List<String> authenticationMethods;
    private List<String> scopes;

    private boolean requireProofKey;
    private boolean requireAuthorizationConsent;

    private long accessTokenTTL;
    private long refreshTokenTTL;
    private boolean reuseRefreshTokens;
}
