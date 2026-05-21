package com.auth.security.auth_security_app.admin.repository;

import com.auth.security.auth_security_app.admin.entity.RoleEntity;
import com.auth.security.auth_security_app.admin.entity.UserEntity;
import com.auth.security.auth_security_app.admin.entity.UserRoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface UserRoleRepository extends JpaRepository<UserRoleEntity, Long> {

    void deleteByUser(UserEntity user);

    boolean existsByUserAndRole(UserEntity user, RoleEntity role);
    @Query("""
    select ur
    from UserRoleEntity ur
    join fetch ur.role
    where ur.user.id = :userId
""")
    List<UserRoleEntity> findByUserIdWithRole(@Param("userId") Long userId);
}
