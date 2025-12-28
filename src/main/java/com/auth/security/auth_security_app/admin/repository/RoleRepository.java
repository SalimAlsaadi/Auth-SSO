package com.auth.security.auth_security_app.admin.repository;

import com.auth.security.auth_security_app.admin.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<RoleEntity, Integer> {

    Optional<RoleEntity> findByRoleName(String roleName);

    boolean existsByRoleName(String roleName);
}
