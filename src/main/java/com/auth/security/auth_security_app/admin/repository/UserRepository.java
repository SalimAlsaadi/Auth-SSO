package com.auth.security.auth_security_app.admin.repository;

import com.auth.security.auth_security_app.admin.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity>findByUsername(String username);

    boolean existsByUsername(String username);

}
