package com.auth.security.auth_security_app.admin.dto.clientDTO;

import lombok.Data;
import java.util.List;

@Data
public class ClientRequest {
    private String clientId;
    private List<String> redirectUris;
    private List<String> postLogoutRedirectUris;
    private List<String> scopes;
    private boolean requireProofKey;
}
