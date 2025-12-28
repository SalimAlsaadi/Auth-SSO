package com.auth.security.auth_security_app.admin.repository;

import com.auth.security.auth_security_app.admin.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity>findByUsername(String username);

    boolean existsByUsername(String username);

    long countByEnabled(boolean enabled);

    @Query("""
    SELECT u FROM UserEntity u
    LEFT JOIN FETCH u.roles ur
    LEFT JOIN FETCH ur.role r
    WHERE u.username = :username
""")
    Optional<UserEntity> findByUsernameWithRoles(String username);

}
