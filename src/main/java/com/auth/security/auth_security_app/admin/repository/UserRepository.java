package com.auth.security.auth_security_app.admin.repository;

import com.auth.security.auth_security_app.admin.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

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

    @Query("""
    SELECT COUNT(DISTINCT u)
    FROM UserEntity u
    JOIN u.roles ur
    JOIN ur.role r
    WHERE r.roleName = :roleName
""")
    long countUsersByRole(@Param("roleName") String roleName);

    @Query("""
    select distinct u
    from UserEntity u
    left join fetch u.roles ur
    left join fetch ur.role r
    left join fetch u.clients uc
    left join fetch uc.client c
    where u.username = :username
""")
    Optional<UserEntity> findByUsernameWithRolesAndClients(@Param("username") String username);

    Optional<UserEntity> findByRefId(Long refId);
}
