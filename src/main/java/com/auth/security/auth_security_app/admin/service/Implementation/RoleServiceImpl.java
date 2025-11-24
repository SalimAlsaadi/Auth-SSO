package com.auth.security.auth_security_app.admin.service.Implementation;

import com.auth.security.auth_security_app.admin.dto.RoleRequest;
import com.auth.security.auth_security_app.admin.entity.PermissionEntity;
import com.auth.security.auth_security_app.admin.entity.RoleEntity;
import com.auth.security.auth_security_app.admin.repository.PermissionRepository;
import com.auth.security.auth_security_app.admin.repository.RoleRepository;
import com.auth.security.auth_security_app.admin.service.Interface.RoleService;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepo;
    private final PermissionRepository permRepo;

    public RoleServiceImpl(RoleRepository roleRepo, PermissionRepository permRepo) {
        this.roleRepo = roleRepo;
        this.permRepo = permRepo;
    }

    @Override
    public RoleEntity createRole(RoleRequest request) {
        Set<PermissionEntity> perms = new HashSet<>();
        for (String key : request.permissions()) {
            permRepo.findByPermKey(key).ifPresent(perms::add);
        }

        RoleEntity role = RoleEntity.builder()
                .roleName(request.roleName())
                .description(request.description())
                .permissions(perms)
                .build();

        return roleRepo.save(role);
    }

    @Override
    public List<RoleEntity> getAllRoles() {
        return roleRepo.findAll();
    }

    @Override
    public RoleEntity updateRole(Integer id, RoleRequest request) {
        RoleEntity role = roleRepo.findById(id)
                .orElseThrow(() -> new RuntimeException("Role not found"));

        role.setRoleName(request.roleName());
        role.setDescription(request.description());

        Set<PermissionEntity> perms = new HashSet<>();
        for (String key : request.permissions()) {
            permRepo.findByPermKey(key).ifPresent(perms::add);
        }
        role.setPermissions(perms);

        return roleRepo.save(role);
    }

    @Override
    public void deleteRole(Integer id) {
        roleRepo.deleteById(id);
    }
}
