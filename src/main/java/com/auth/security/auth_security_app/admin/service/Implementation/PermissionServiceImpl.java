package com.auth.security.auth_security_app.admin.service.Implementation;

import com.auth.security.auth_security_app.admin.dto.PermissionRequest;
import com.auth.security.auth_security_app.admin.entity.PermissionEntity;
import com.auth.security.auth_security_app.admin.repository.PermissionRepository;
import com.auth.security.auth_security_app.admin.service.Interface.PermissionService;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PermissionServiceImpl implements PermissionService {

    private final PermissionRepository repo;

    public PermissionServiceImpl(PermissionRepository repo) {
        this.repo = repo;
    }

    @Override
    public PermissionEntity createPermission(PermissionRequest req) {
        PermissionEntity p = PermissionEntity.builder()
                .permKey(req.permKey())
                .description(req.description())
                .build();

        return repo.save(p);
    }

    @Override
    public List<PermissionEntity> getAllPermissions() {
        return repo.findAll();
    }
}
