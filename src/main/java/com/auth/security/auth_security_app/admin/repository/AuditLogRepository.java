package com.auth.security.auth_security_app.admin.repository;

import com.auth.security.auth_security_app.admin.entity.AuditLogEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogRepository extends JpaRepository<AuditLogEntity, Long> {


        Page<AuditLogEntity> findByActorUserId(Long actorUserId, Pageable pageable);

        Page<AuditLogEntity> findByAction(String action, Pageable pageable);

        Page<AuditLogEntity> findByActorUserIdAndAction(Long actorUserId, String action, Pageable pageable);
    }


