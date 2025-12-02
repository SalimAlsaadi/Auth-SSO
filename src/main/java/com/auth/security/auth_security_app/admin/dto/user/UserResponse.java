package com.auth.security.auth_security_app.admin.dto.user;

import lombok.Data;

import java.util.List;

@Data
public class UserResponse {

    private Long userId;
    private String username;
    private boolean enabled;

    private String refType;
    private Long refId;

    private List<String> roles;
    private List<String> allowedClients;
}
