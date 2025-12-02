package com.auth.security.auth_security_app.admin.dto.permissionDTO;

import lombok.Data;

@Data
public class PermissionResponse {

    private Long id;
    private String permissionName;
    private String description;
}
