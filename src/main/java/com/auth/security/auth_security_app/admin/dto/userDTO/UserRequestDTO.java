package com.auth.security.auth_security_app.admin.dto.userDTO;

import lombok.Data;

import java.util.List;

@Data
public class UserRequestDTO {

    private Long userId;
    private String username;
    private String password;
    private String refType;
    private Long refId;

    private boolean enabled;

    private List<Integer> roleIds;       // Assign roles
    private List<String> allowedClients; // Assign allowed clients
}
