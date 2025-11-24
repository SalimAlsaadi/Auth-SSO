package com.auth.security.auth_security_app.admin.service.Interface;

import com.auth.security.auth_security_app.admin.dto.RoleRequest;
import com.auth.security.auth_security_app.admin.entity.RoleEntity;

import java.util.List;

public interface RoleService {
    RoleEntity createRole(RoleRequest request);
    List<RoleEntity> getAllRoles();
    RoleEntity updateRole(Integer id, RoleRequest request);
    void deleteRole(Integer id);
}
