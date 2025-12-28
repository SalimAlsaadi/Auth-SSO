package com.auth.security.auth_security_app.admin.dto.auditDTO;

import lombok.Data;

@Data
public class AuditLogRequest {
    private Long actorUserId;
    private String action;
    private String entityType;
    private String entityId;
    private String details;
}
