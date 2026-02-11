package com.auth.security.auth_security_app.admin.dto.clientDTO;

import lombok.Data;
import java.util.List;

@Data
public class ClientRequestDTO {

    private String clientId;
    private String clientCode;
    private String clientName;
    private String clientDescription;
    private List<String> redirectUris;
    private List<String> postLogoutRedirectUris;
    private List<String> scopes;
    private boolean requireProofKey;
}
