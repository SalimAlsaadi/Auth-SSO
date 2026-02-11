package com.auth.security.auth_security_app.admin.dto.roleDTO;

import com.auth.security.auth_security_app.admin.entity.PermissionEntity;
import lombok.Data;
import java.util.List;

@Data
public class RoleResponseDTO {

    private Integer id;
    private String roleName;
    private String description;

    // List of assigned permissions (permission names)
    private List<PermissionEntity> permissions;
}
