package com.auth.security.auth_security_app.admin.dto.roleDTO;

import com.auth.security.auth_security_app.admin.entity.PermissionEntity;
import com.auth.security.auth_security_app.admin.entity.RolePermissionEntity;
import lombok.Data;
import java.util.List;

@Data
public class RoleResponse {

    private Integer id;
    private String roleName;
    private String description;

    // List of assigned permissions (permission names)
    private List<PermissionEntity> permissions;
}
