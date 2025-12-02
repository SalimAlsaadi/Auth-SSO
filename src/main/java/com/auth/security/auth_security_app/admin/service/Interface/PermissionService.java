package com.auth.security.auth_security_app.admin.service.Interface;

import com.auth.security.auth_security_app.admin.dto.permissionDTO.PermissionRequest;
import com.auth.security.auth_security_app.admin.dto.permissionDTO.PermissionResponse;

import java.util.List;

public interface PermissionService {

    PermissionResponse create(PermissionRequest request);

    PermissionResponse update(Long permissionId, PermissionRequest request);

    String delete(Long permissionId);

    List<PermissionResponse> getAll();

    PermissionResponse getById(Long permissionId);
}
