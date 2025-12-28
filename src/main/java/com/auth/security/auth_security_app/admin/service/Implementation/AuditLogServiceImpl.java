package com.auth.security.auth_security_app.admin.service.Implementation;

import com.auth.security.auth_security_app.admin.dto.auditDTO.AuditLogResponse;
import com.auth.security.auth_security_app.admin.entity.AuditLogEntity;
import com.auth.security.auth_security_app.admin.repository.AuditLogRepository;
import com.auth.security.auth_security_app.admin.service.Interface.AuditLogService;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuditLogServiceImpl implements AuditLogService {

    private final AuditLogRepository repo;

    @Override
    public void log(Long actorId, String action, String entityType, String entityId, String details) {

        AuditLogEntity log = AuditLogEntity.builder()
                .actorUserId(actorId)
                .action(action)
                .entityType(entityType)
                .entityId(entityId)
                .details(details)
                .timestamp(LocalDateTime.now())
                .build();

        repo.save(log);
    }

    @Override
    public Page<AuditLogResponse> getAuditLogs(Long actorUserId, String action, Pageable pageable) {

        Page<AuditLogEntity> page;

        if (actorUserId != null && action != null) {
            page = repo.findByActorUserIdAndAction(actorUserId, action, pageable);
        }
        else if (actorUserId != null) {
            page = repo.findByActorUserId(actorUserId, pageable);
        }
        else if (action != null) {
            page = repo.findByAction(action, pageable);
        }
        else {
            page = repo.findAll(pageable);
        }

        return page.map(this::toDTO);
    }

    @Override
    public AuditLogResponse getById(Long id) {
        return repo.findById(id)
                .map(this::toDTO)
                .orElseThrow(() -> new RuntimeException("Audit log not found"));
    }




    private AuditLogResponse toDTO(AuditLogEntity entity) {

        AuditLogResponse dto = new AuditLogResponse();

        dto.setId(entity.getId());
        dto.setActorUserId(entity.getActorUserId());
        dto.setAction(entity.getAction());
        dto.setEntityType(entity.getEntityType());
        dto.setEntityId(entity.getEntityId());
        dto.setDetails(entity.getDetails());
        dto.setTimestamp(entity.getTimestamp());

        return dto;
    }

}
