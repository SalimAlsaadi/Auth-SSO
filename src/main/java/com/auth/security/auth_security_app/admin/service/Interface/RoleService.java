package com.auth.security.auth_security_app.admin.service.Interface;

import com.auth.security.auth_security_app.admin.dto.roleDTO.RoleRequest;
import com.auth.security.auth_security_app.admin.dto.roleDTO.RoleResponse;

import java.util.List;

public interface RoleService {

    RoleResponse create(RoleRequest request);

    RoleResponse update(Integer roleId, RoleRequest request);

    String delete(Integer roleId);

    List<RoleResponse> getAll();

    RoleResponse getById(Integer roleId);

    RoleResponse addPermission(Integer roleId, Long permissionId);

    RoleResponse removePermission(Integer roleId, Long permissionId);
}
