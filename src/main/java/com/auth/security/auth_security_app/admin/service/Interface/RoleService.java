package com.auth.security.auth_security_app.admin.service.Interface;

import com.auth.security.auth_security_app.admin.dto.roleDTO.RoleRequest;
import com.auth.security.auth_security_app.admin.dto.roleDTO.RoleResponse;

import java.util.List;

public interface RoleService {

    RoleResponse create(RoleRequest request);

    RoleResponse update(Long roleId, RoleRequest request);

    String delete(Long roleId);

    List<RoleResponse> getAll();

    RoleResponse getById(Long roleId);

    RoleResponse addPermission(Long roleId, Long permissionId);

    RoleResponse removePermission(Long roleId, Long permissionId);
}
