package com.auth.security.auth_security_app.admin.service.Interface;

import com.auth.security.auth_security_app.admin.dto.permissionDTO.PermissionRequestDTO;
import com.auth.security.auth_security_app.admin.dto.permissionDTO.PermissionResponseDTO;

import java.util.List;

public interface PermissionService {

    PermissionResponseDTO create(PermissionRequestDTO request);

    PermissionResponseDTO update(Long permissionId, PermissionRequestDTO request);

    String delete(Long permissionId);

    List<PermissionResponseDTO> getAll();

    PermissionResponseDTO getById(Long permissionId);
}
