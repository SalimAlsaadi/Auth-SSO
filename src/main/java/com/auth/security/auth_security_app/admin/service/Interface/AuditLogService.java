package com.auth.security.auth_security_app.admin.service.Interface;


import com.auth.security.auth_security_app.admin.dto.auditDTO.AuditLogResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface AuditLogService {


    void log(Long actorId, String action, String entityType, String entityId, String details);

    Page<AuditLogResponse> getAuditLogs(Long actorUserId, String action, Pageable pageable);

    AuditLogResponse getById(Long id);

}
