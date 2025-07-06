package com.auth.security.auth_security_app.Repository;

import com.auth.security.auth_security_app.DATA.Entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity>findByUsername(String username);
}
