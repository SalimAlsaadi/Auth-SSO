package com.auth.security.auth_security_app.admin.service.Interface;


import com.auth.security.auth_security_app.admin.dto.auditDTO.AuditLogResponseDTO;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface AuditLogService {


    void log(Long actorId, String action, String entityType, String entityId, String details);

    Page<AuditLogResponseDTO> getAuditLogs(Long actorUserId, String action, Pageable pageable);

    AuditLogResponseDTO getById(Long id);

}
