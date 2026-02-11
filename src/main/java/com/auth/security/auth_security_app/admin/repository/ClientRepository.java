package com.auth.security.auth_security_app.admin.repository;

import com.auth.security.auth_security_app.admin.entity.ClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ClientRepository extends JpaRepository<ClientEntity, Integer> {

    // Get ONE client by business code
    Optional<ClientEntity> findByClientCode(String clientCode);

    // ✅ Get ONE client by OAuth clientId
    Optional<ClientEntity> findByOauthClientId(String oauthClientId);

    // ✅ Get MANY clients by OAuth clientIds
    List<ClientEntity> findByOauthClientIdIn(List<String> oauthClientIds);
}
