package com.auth.security.auth_security_app.admin.service.Implementation;

import com.auth.security.auth_security_app.admin.dto.roleDTO.RoleRequestDTO;
import com.auth.security.auth_security_app.admin.dto.roleDTO.RoleResponseDTO;
import com.auth.security.auth_security_app.admin.entity.PermissionEntity;
import com.auth.security.auth_security_app.admin.entity.RoleEntity;
import com.auth.security.auth_security_app.admin.entity.RolePermissionEntity;
import com.auth.security.auth_security_app.admin.entity.UserEntity;
import com.auth.security.auth_security_app.admin.repository.PermissionRepository;
import com.auth.security.auth_security_app.admin.repository.RoleRepository;
import com.auth.security.auth_security_app.admin.repository.UserRepository;
import com.auth.security.auth_security_app.admin.service.Interface.AuditLogService;
import com.auth.security.auth_security_app.admin.service.Interface.RoleService;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;


    @Override
    public RoleResponseDTO create(RoleRequestDTO request) {

        if (roleRepository.existsByRoleName(request.getRoleName())) {
            throw new RuntimeException("Role name already exists");
        }

        RoleEntity role = new RoleEntity();
        role.setRoleName(request.getRoleName());
        role.setDescription(request.getDescription());

        RoleResponseDTO roleResponse=toDTO(roleRepository.save(role));
        auditLogService.log(
                currentUserId(),
                "ROLE_ASSIGN",
                "ROLE",
                roleResponse.getId().toString(),
                "Assigned roles: " + roleResponse.getRoleName()
        );


        return roleResponse;
    }

    @Override
    public RoleResponseDTO update(Integer roleId, RoleRequestDTO request) {

        RoleEntity role = roleRepository.findById(roleId)
                .orElseThrow(() -> new RuntimeException("Role not found"));

        role.setRoleName(request.getRoleName());
        role.setDescription(request.getDescription());

        return toDTO(roleRepository.save(role));
    }

    @Override
    public String delete(Integer roleId) {
        roleRepository.deleteById(roleId);
        return "Role deleted";
    }

    @Override
    public List<RoleResponseDTO> getAll() {
        return roleRepository.findAll()
                .stream()
                .map(this::toDTO)
                .toList();
    }

    @Override
    public RoleResponseDTO getById(Integer roleId) {
        return roleRepository.findById(roleId)
                .map(this::toDTO)
                .orElseThrow(() -> new RuntimeException("Role not found"));
    }

    @Override
    public RoleResponseDTO addPermission(Integer roleId, Long permissionId) {

        RoleEntity role = roleRepository.findById(roleId)
                .orElseThrow(() -> new RuntimeException("Role not found"));

        PermissionEntity perm = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new RuntimeException("Permission not found"));

        boolean exists = role.getRolePermissions().stream()
                .anyMatch(rp -> rp.getPermission().getPerm_id().equals(permissionId));

        if (exists) {
            throw new RuntimeException("Permission already assigned to role");
        }

        RolePermissionEntity rp = new RolePermissionEntity();
        rp.setRole(role);
        rp.setPermission(perm);

        role.getRolePermissions().add(rp);

        auditLogService.log(
                currentUserId(),
                "PERMISSION_ADD",
                "ROLE",
                roleId.toString(),
                "Added permission " + permissionId
        );

        return toDTO(roleRepository.save(role));
    }


    @Override
    public RoleResponseDTO removePermission(Integer roleId, Long permissionId) {

        RoleEntity role = roleRepository.findById(roleId)
                .orElseThrow(() -> new RuntimeException("Role not found"));

        RolePermissionEntity target = role.getRolePermissions().stream()
                .filter(rp -> rp.getPermission().getPerm_id().equals(permissionId))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Permission not assigned to role"));

        role.getRolePermissions().remove(target);

        auditLogService.log(
                currentUserId(),
                "PERMISSION_REMOVE",
                "ROLE",
                roleId.toString(),
                "Removed permission " + permissionId
        );

        return toDTO(roleRepository.save(role));
    }



    private RoleResponseDTO toDTO(RoleEntity role) {
        RoleResponseDTO dto = new RoleResponseDTO();

        dto.setId(role.getRoleId());
        dto.setRoleName(role.getRoleName());
        dto.setDescription(role.getDescription());

        dto.setPermissions(
                role.getRolePermissions().stream()
                        .map(RolePermissionEntity::getPermission)
                        .toList()
        );

        return dto;
    }


    //log helper
    private Long currentUserId() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return userRepository.findByUsername(username)
                .map(UserEntity::getId)
                .orElse(null);
    }

}
