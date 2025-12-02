package com.auth.security.auth_security_app.admin.dto.user;

import lombok.Data;

import java.util.List;

@Data
public class UserRequest {

    private String username;
    private String password;
    private String refType;
    private Long refId;

    private boolean enabled;

    private List<Long> roleIds;       // Assign roles
    private List<String> allowedClients; // Assign allowed clients
}
