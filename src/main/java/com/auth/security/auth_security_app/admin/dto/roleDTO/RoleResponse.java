package com.auth.security.auth_security_app.admin.dto.roleDTO;

import lombok.Data;
import java.util.List;

@Data
public class RoleResponse {

    private Long id;
    private String roleName;
    private String description;

    // List of assigned permissions (permission names)
    private List<String> permissions;
}
