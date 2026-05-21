package com.auth.security.auth_security_app.admin.dto.userDTO;

import lombok.Data;

import java.util.List;

@Data
public class UserRequestDTO {

    private Long userId;
    private String username;
    private String password;

    private Boolean enabled;

    private Integer roleIds;       // Assign roles
    private String allowedClients; // Assign allowed clients
}
