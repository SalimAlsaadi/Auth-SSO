package com.auth.security.auth_security_app.admin.repository;

import com.auth.security.auth_security_app.admin.entity.ClientEntity;
import com.auth.security.auth_security_app.admin.entity.UserClientEntity;
import com.auth.security.auth_security_app.admin.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface UserClientRepository extends JpaRepository<UserClientEntity, Long> {

    void deleteByUser(UserEntity user);

    boolean existsByUserAndClient(UserEntity user, ClientEntity client);
}
