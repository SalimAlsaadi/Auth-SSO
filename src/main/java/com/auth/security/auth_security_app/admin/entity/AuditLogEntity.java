package com.auth.security.auth_security_app.admin.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class AuditLogEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long actorUserId;     // admin who performed the action

    @Column(nullable = false, length = 50)
    private String action;        // USER_CREATE, ROLE_ASSIGN, CLIENT_UPDATE...

    @Column(nullable = false, length = 50)
    private String entityType;    // User, Role, Client, Permission

    private String entityId;      // which record was affected

    @Column(columnDefinition = "TEXT")
    private String details;       // JSON details or simple note

    private LocalDateTime timestamp;
}
