package com.auth.security.auth_security_app.admin.service.Interface;

import com.auth.security.auth_security_app.admin.dto.PermissionRequest;
import com.auth.security.auth_security_app.admin.entity.PermissionEntity;

import java.util.List;

public interface PermissionService {
    PermissionEntity createPermission(PermissionRequest req);
    List<PermissionEntity> getAllPermissions();
}
