package com.auth.security.auth_security_app.admin.service.Interface;

import com.auth.security.auth_security_app.admin.dto.roleDTO.RoleRequestDTO;
import com.auth.security.auth_security_app.admin.dto.roleDTO.RoleResponseDTO;

import java.util.List;

public interface RoleService {

    RoleResponseDTO create(RoleRequestDTO request);

    RoleResponseDTO update(Integer roleId, RoleRequestDTO request);

    String delete(Integer roleId);

    List<RoleResponseDTO> getAll();

    RoleResponseDTO getById(Integer roleId);

    RoleResponseDTO addPermission(Integer roleId, Long permissionId);

    RoleResponseDTO removePermission(Integer roleId, Long permissionId);
}
