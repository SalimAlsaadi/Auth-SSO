package com.auth.security.auth_security_app.admin.repository;

import com.auth.security.auth_security_app.admin.entity.UserEntity;
import com.auth.security.auth_security_app.admin.entity.UserRoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRoleRepository extends JpaRepository<UserRoleEntity, Long> {

    void deleteByUser(UserEntity user);

}
