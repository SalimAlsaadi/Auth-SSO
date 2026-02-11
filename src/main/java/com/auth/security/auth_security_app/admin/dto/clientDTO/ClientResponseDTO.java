package com.auth.security.auth_security_app.admin.dto.clientDTO;

import lombok.Data;
import java.util.List;

@Data
public class ClientResponseDTO {
    private Integer id;
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

    private String clientCode;
    private String clientDescription;

}
