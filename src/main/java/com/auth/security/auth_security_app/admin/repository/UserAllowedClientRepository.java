package com.auth.security.auth_security_app.admin.repository;

import com.auth.security.auth_security_app.admin.entity.UserAllowedClientEntity;
import com.auth.security.auth_security_app.admin.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserAllowedClientRepository extends JpaRepository<UserAllowedClientEntity, Long> {

    void deleteByUser(UserEntity user);
}
