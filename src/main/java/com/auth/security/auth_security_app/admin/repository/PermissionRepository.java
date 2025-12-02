package com.auth.security.auth_security_app.admin.repository;

import com.auth.security.auth_security_app.admin.entity.PermissionEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PermissionRepository extends JpaRepository<PermissionEntity, Long> {

    boolean existsByPermissionName(String permissionName);

    Optional<PermissionEntity> findByPermissionName(String permissionName);
}
