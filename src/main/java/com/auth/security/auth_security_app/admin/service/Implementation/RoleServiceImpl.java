package com.auth.security.auth_security_app.admin.service.Implementation;

import com.auth.security.auth_security_app.admin.dto.roleDTO.RoleRequest;
import com.auth.security.auth_security_app.admin.dto.roleDTO.RoleResponse;
import com.auth.security.auth_security_app.admin.entity.PermissionEntity;
import com.auth.security.auth_security_app.admin.entity.RoleEntity;
import com.auth.security.auth_security_app.admin.repository.PermissionRepository;
import com.auth.security.auth_security_app.admin.repository.RoleRepository;
import com.auth.security.auth_security_app.admin.service.Interface.RoleService;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    @Override
    public RoleResponse create(RoleRequest request) {

        if (roleRepository.existsByRoleName(request.getRoleName())) {
            throw new RuntimeException("Role name already exists");
        }

        RoleEntity role = new RoleEntity();
        role.setRoleName(request.getRoleName());
        role.setDescription(request.getDescription());

        return toDTO(roleRepository.save(role));
    }

    @Override
    public RoleResponse update(Long roleId, RoleRequest request) {

        RoleEntity role = roleRepository.findById(roleId)
                .orElseThrow(() -> new RuntimeException("Role not found"));

        role.setRoleName(request.getRoleName());
        role.setDescription(request.getDescription());

        return toDTO(roleRepository.save(role));
    }

    @Override
    public String delete(Long roleId) {
        roleRepository.deleteById(roleId);
        return "Role deleted";
    }

    @Override
    public List<RoleResponse> getAll() {
        return roleRepository.findAll()
                .stream()
                .map(this::toDTO)
                .toList();
    }

    @Override
    public RoleResponse getById(Long roleId) {
        return roleRepository.findById(roleId)
                .map(this::toDTO)
                .orElseThrow(() -> new RuntimeException("Role not found"));
    }

    @Override
    public RoleResponse addPermission(Long roleId, Long permissionId) {

        RoleEntity role = roleRepository.findById(roleId)
                .orElseThrow(() -> new RuntimeException("Role not found"));

        PermissionEntity perm = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new RuntimeException("Permission not found"));

        role.getPermissions().add(perm);

        return toDTO(roleRepository.save(role));
    }

    @Override
    public RoleResponse removePermission(Long roleId, Long permissionId) {

        RoleEntity role = roleRepository.findById(roleId)
                .orElseThrow(() -> new RuntimeException("Role not found"));

        PermissionEntity perm = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new RuntimeException("Permission not found"));

        role.getPermissions().remove(perm);

        return toDTO(roleRepository.save(role));
    }


    private RoleResponse toDTO(RoleEntity role) {
        RoleResponse dto = new RoleResponse();

        dto.setId(role.getRoleId());
        dto.setRoleName(role.getRoleName());
        dto.setDescription(role.getDescription());

        dto.setPermissions(
                role.getPermissions()
                        .stream()
                        .map(PermissionEntity::getPermissionName)
                        .toList()
        );

        return dto;
    }
}
